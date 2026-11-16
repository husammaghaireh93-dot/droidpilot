package com.mobilemcp.pro.server

import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.mobilemcp.pro.model.CommandRequest
import com.mobilemcp.pro.model.CommandResponse
import com.mobilemcp.pro.service.MobileAccessibilityService
import org.java_websocket.WebSocket
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.server.WebSocketServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.concurrent.Executors

class WebSocketCommandServer(
    port: Int,
    private val onLog: (String) -> Unit,
    private val onConnectionChange: (Int) -> Unit
) : WebSocketServer(InetSocketAddress("127.0.0.1", port)) {

    companion object {
        private const val TAG = "WSCommandServer"

        fun isLoopbackRemote(address: InetAddress?): Boolean {
            return address != null && address.isLoopbackAddress
        }
    }

    private val gson = Gson()
    private val executor = Executors.newFixedThreadPool(4)
    private val connectedClients = mutableSetOf<WebSocket>()

    // Enforced: must be populated with a cryptographic secret before accepting connections
    @Volatile
    var authToken: String = ""

    private fun safeLogInfo(msg: String) {
        try {
            Log.i(TAG, msg)
        } catch (_: Throwable) {
            // Pure-JVM unit tests run without Android Log implementation
        }
    }

    private fun safeLogError(msg: String, ex: Throwable) {
        try {
            Log.e(TAG, msg, ex)
        } catch (_: Throwable) {
            // Pure-JVM unit tests run without Android Log implementation
        }
    }

    /**
     * Rotates the active Bearer token and immediately disconnects all existing
     * WebSocket sessions so stale clients cannot continue sending commands.
     */
    fun rotateAuthToken(newToken: String) {
        authToken = newToken
        val toClose = synchronized(connectedClients) {
            val snapshot = connectedClients.toList()
            connectedClients.clear()
            snapshot
        }
        for (client in toClose) {
            try {
                client.close(4001, "Unauthorized: Auth token rotated")
            } catch (_: Exception) {}
        }
        onConnectionChange(0)
        onLog("Auth token rotated; closed ${toClose.size} active connection(s)")
    }

    fun isAuthorizedHandshake(authorizationHeader: String?): Boolean {
        val currentToken = authToken
        if (currentToken.isEmpty() || authorizationHeader.isNullOrBlank()) return false
        val expected = "Bearer $currentToken".toByteArray(Charsets.UTF_8)
        val provided = authorizationHeader.toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(expected, provided)
    }

    override fun onOpen(conn: WebSocket, handshake: ClientHandshake) {
        val remoteSocket = conn.remoteSocketAddress
        val remoteAddr = remoteSocket?.toString() ?: "unknown"
        safeLogInfo("Client connecting: $remoteAddr")

        if (!isLoopbackRemote(remoteSocket?.address)) {
            conn.close(4003, "Forbidden: Loopback connections only")
            onLog("Client rejected (non-loopback): $remoteAddr")
            return
        }

        val providedToken = handshake.getFieldValue("Authorization")
        if (!isAuthorizedHandshake(providedToken)) {
            conn.close(4001, "Unauthorized: Invalid or missing token")
            onLog("Client rejected (bad token): $remoteAddr")
            return
        }

        onLog("Client connected: $remoteAddr")
        synchronized(connectedClients) {
            connectedClients.add(conn)
        }
        onConnectionChange(connectedClients.size)
    }

    override fun onClose(conn: WebSocket, code: Int, reason: String, remote: Boolean) {
        val remoteAddr = conn.remoteSocketAddress?.toString() ?: "unknown"
        safeLogInfo("Client disconnected: $remoteAddr")
        onLog("Client disconnected: $remoteAddr")
        val remaining = synchronized(connectedClients) {
            connectedClients.remove(conn)
            connectedClients.size
        }
        onConnectionChange(remaining)
    }

    override fun onMessage(conn: WebSocket, message: String) {
        executor.submit {
            try {
                val request = gson.fromJson(message, CommandRequest::class.java)
                if (request.command == null) {
                    sendError(conn, null, "Missing 'command' field")
                    return@submit
                }

                onLog(">> ${request.command}")

                val service = MobileAccessibilityService.instance
                if (service == null) {
                    sendError(conn, request.id, "Accessibility service is not running. Enable it in Settings.")
                    return@submit
                }

                val response = service.handleCommand(request)
                val finalResponse = response.copy(id = request.id)
                val json = gson.toJson(finalResponse)
                conn.send(json)

                onLog("<< ${request.command}: ${if (finalResponse.success) "OK" else "ERR"}")

            } catch (e: JsonSyntaxException) {
                sendError(conn, null, "Invalid JSON: ${e.message}")
            } catch (e: Exception) {
                safeLogError("Error processing message", e)
                sendError(conn, null, "Internal error: ${e.message}")
            }
        }
    }

    override fun onError(conn: WebSocket?, ex: Exception) {
        safeLogError("WebSocket error", ex)
        onLog("Error: ${ex.message}")
    }

    override fun onStart() {
        safeLogInfo("WebSocket server started on 127.0.0.1:${this.port}")
        onLog("Server started on 127.0.0.1:${this.port}")
        connectionLostTimeout = 60
    }

    fun getConnectionCount(): Int = synchronized(connectedClients) { connectedClients.size }

    private fun sendError(conn: WebSocket, id: String?, message: String) {
        val response = CommandResponse.error(id, message)
        conn.send(gson.toJson(response))
        onLog("<< ERROR: $message")
    }

    fun shutdown() {
        try {
            executor.shutdownNow()
            stop(1000)
        } catch (e: Exception) {
            safeLogError("Error shutting down", e)
        }
    }
}
