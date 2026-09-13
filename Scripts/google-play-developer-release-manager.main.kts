#!/usr/bin/env kotlin
// Copyright 2026 RefineID contributors. Licensed under the Apache License, Version 2.0.
//
// Drive the complete Google Play Developer release lifecycle in Kotlin
// with zero external dependencies (pure standard JVM / Kotlin runtime).
//
// Commands:
//   google-play-developer-release-manager.main.kts status
//   google-play-developer-release-manager.main.kts tracks
//   google-play-developer-release-manager.main.kts testers <internal|alpha|beta|production>
//   google-play-developer-release-manager.main.kts add-group <track> <groupEmail>
//   google-play-developer-release-manager.main.kts remove-group <track> <groupEmail>
//   google-play-developer-release-manager.main.kts sync-groups <track> <groupsFile>
//   google-play-developer-release-manager.main.kts promote <fromTrack> <toTrack>
//   google-play-developer-release-manager.main.kts listings
//   google-play-developer-release-manager.main.kts api <METHOD> <path> [jsonBody]

import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.system.exitProcess

val APP_PACKAGE = "fi.refineid.android"
val SCOPE = "https://www.googleapis.com/auth/androidpublisher"
val API_BASE = "https://androidpublisher.googleapis.com/androidpublisher/v3"

fun fail(message: String): Nothing {
    System.err.println("FAIL: $message")
    exitProcess(1)
}

fun note(message: String) {
    println("  ok: $message")
}

class GooglePlayClient(val serviceAccountFile: File) {
    private val httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .build()

    private var cachedToken: String? = null
    private var tokenExpiry: Long = 0

    private fun getAccessToken(): String {
        val now = Instant.now().epochSecond
        if (cachedToken != null && now < tokenExpiry - 60) {
            return cachedToken!!
        }

        if (!serviceAccountFile.exists()) {
            fail("Service account file not found: ${serviceAccountFile.absolutePath}")
        }

        val json = serviceAccountFile.readText()
        val clientEmailRegex = "\"client_email\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val clientEmail = clientEmailRegex.find(json)?.groupValues?.get(1)
            ?: fail("client_email not found in ${serviceAccountFile.name}")

        val privateKeyRegex = "\"private_key\"\\s*:\\s*\"([\\s\\S]*?)\"".toRegex()
        val rawPrivateKey = privateKeyRegex.find(json)?.groupValues?.get(1)
            ?: fail("private_key not found in ${serviceAccountFile.name}")

        val cleanKey = rawPrivateKey
            .replace("\\n", "\n")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\s+".toRegex(), "")

        val keyBytes = try {
            Base64.getDecoder().decode(cleanKey)
        } catch (e: Exception) {
            fail("Invalid base64 in service account private_key: ${e.message}")
        }

        val spec = PKCS8EncodedKeySpec(keyBytes)
        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec)

        val b64url = Base64.getUrlEncoder().withoutPadding()
        val header = b64url.encodeToString("""{"alg":"RS256","typ":"JWT"}""".toByteArray())
        val payload = b64url.encodeToString(
            """{"iss":"$clientEmail","scope":"$SCOPE","aud":"https://oauth2.googleapis.com/token","exp":${now + 3600},"iat":$now}""".toByteArray()
        )

        val signingInput = "$header.$payload"
        val signer = Signature.getInstance("SHA256withRSA").apply {
            initSign(privateKey)
            update(signingInput.toByteArray())
        }
        val sig = signer.sign()
        val jwt = "$signingInput.${b64url.encodeToString(sig)}"

        val formBody = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$jwt"
        val req = HttpRequest.newBuilder(URI.create("https://oauth2.googleapis.com/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formBody))
            .build()

        val resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString())
        if (resp.statusCode() != 200) {
            fail("Failed to obtain OAuth token (${resp.statusCode()}): ${resp.body()}")
        }

        val tokenRegex = "\"access_token\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val token = tokenRegex.find(resp.body())?.groupValues?.get(1)
            ?: fail("Could not parse access_token from response: ${resp.body()}")

        cachedToken = token
        tokenExpiry = now + 3600
        return token
    }

    fun request(method: String, url: String, body: String? = null): HttpResponse<String> {
        val token = getAccessToken()
        val builder = HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer $token")

        when (method.uppercase()) {
            "GET" -> builder.GET()
            "DELETE" -> builder.DELETE()
            "POST" -> {
                builder.header("Content-Type", "application/json")
                builder.POST(body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            }
            "PUT" -> {
                builder.header("Content-Type", "application/json")
                builder.PUT(body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            }
            "PATCH" -> {
                builder.header("Content-Type", "application/json")
                builder.method("PATCH", body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            }
            else -> fail("Unsupported HTTP method: $method")
        }

        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    fun <T> withEdit(block: (editId: String) -> T): T {
        val createResp = request("POST", "$API_BASE/applications/$APP_PACKAGE/edits")
        if (createResp.statusCode() !in 200..299) {
            fail("Failed to create app edit session: ${createResp.body()}")
        }
        val editIdRegex = "\"id\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val editId = editIdRegex.find(createResp.body())?.groupValues?.get(1)
            ?: fail("Failed to parse edit id: ${createResp.body()}")

        try {
            return block(editId)
        } finally {
            request("DELETE", "$API_BASE/applications/$APP_PACKAGE/edits/$editId")
        }
    }

    fun commitEdit(editId: String) {
        val commitResp = request("POST", "$API_BASE/applications/$APP_PACKAGE/edits/$editId:commit")
        if (commitResp.statusCode() !in 200..299) {
            fail("Failed to commit edit session $editId: ${commitResp.body()}")
        }
        note("Changes committed successfully to Google Play Console.")
    }
}

fun findServiceAccountFile(): File {
    val localFile = File("play-service-account.json")
    if (localFile.exists()) return localFile

    val propFile = File("play.properties")
    if (propFile.exists()) {
        val propPath = propFile.readLines().firstOrNull { it.startsWith("serviceAccountCredentials=") }
            ?.substringAfter("=")?.trim()
        if (propPath != null) {
            val f = File(propPath)
            if (f.exists()) return f
        }
    }
    fail("Could not find play-service-account.json in working directory or play.properties")
}

fun extractReleasesArray(json: String): String? {
    val keyIndex = json.indexOf("\"releases\"")
    if (keyIndex < 0) return null
    val arrayStart = json.indexOf('[', keyIndex)
    if (arrayStart < 0) return null
    var depth = 0
    var inString = false
    var escaped = false
    var index = arrayStart
    while (index < json.length) {
        val c = json[index]
        if (inString) {
            if (escaped) {
                escaped = false
            } else if (c == '\\') {
                escaped = true
            } else if (c == '"') {
                inString = false
            }
        } else {
            when (c) {
                '"' -> inString = true
                '[' -> depth++
                ']' -> {
                    depth--
                    if (depth == 0) return json.substring(arrayStart, index + 1)
                }
            }
        }
        index++
    }
    return null
}

fun parseGoogleGroups(json: String): MutableList<String> {
    val groups = mutableListOf<String>()
    val match = "\"googleGroups\"\\s*:\\s*\\[([^\\]]*)\\]".toRegex().find(json) ?: return groups
    val items = match.groupValues[1]
    "\"([^\"]+)\"".toRegex().findAll(items).forEach {
        groups.add(it.groupValues[1])
    }
    return groups
}

fun printUsage() {
    println("""
Google Play Developer Release & Tester Manager (Kotlin)
Usage:
  google-play-developer-release-manager.main.kts status
      Display app package status, tracks, releases, and active tester groups.

  google-play-developer-release-manager.main.kts tracks
      List tracks (internal, alpha, beta, production) and rollout versions.

  google-play-developer-release-manager.main.kts testers <track>
      List Google Groups linked to the specified track (e.g. internal, alpha).

  google-play-developer-release-manager.main.kts add-group <track> <groupEmail>
      Add/link a Google Group (e.g. refineid-test@googlegroups.com) to a track.

  google-play-developer-release-manager.main.kts remove-group <track> <groupEmail>
      Remove a Google Group from the specified track.

  google-play-developer-release-manager.main.kts sync-groups <track> <groupsFile>
      Synchronize a list of Google Groups from a newline-delimited text file.

  google-play-developer-release-manager.main.kts promote <fromTrack> <toTrack>
      Promote active releases from one track to another (e.g. internal -> alpha).

  google-play-developer-release-manager.main.kts listings
      Display store presence listings and descriptions across locales.

  google-play-developer-release-manager.main.kts api <METHOD> <path> [jsonBody]
      Execute arbitrary Google Play Developer API request.
""".trimIndent())
}

fun main(args: Array<String>) {
    if (args.isEmpty() || args[0] in listOf("-h", "--help", "help")) {
        printUsage()
        return
    }

    val command = args[0]
    val client = GooglePlayClient(findServiceAccountFile())

    when (command) {
        "status" -> {
            println("== RefineID Google Play Status ($APP_PACKAGE) ==")
            client.withEdit { editId ->
                val tracksResp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/tracks")
                println("\nTracks & Releases:\n${tracksResp.body()}")

                println("\nTester Groups by Track:")
                for (track in listOf("internal", "alpha", "beta")) {
                    val testerResp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track")
                    val groups = parseGoogleGroups(testerResp.body())
                    if (groups.isEmpty()) {
                        println("  [$track]: (no Google Groups attached)")
                    } else {
                        println("  [$track]: ${groups.joinToString(", ")}")
                    }
                }
            }
        }

        "tracks" -> {
            client.withEdit { editId ->
                val resp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/tracks")
                println(resp.body())
            }
        }

        "testers" -> {
            if (args.size < 2) fail("Usage: testers <internal|alpha|beta|production>")
            val track = args[1]
            client.withEdit { editId ->
                val resp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track")
                val groups = parseGoogleGroups(resp.body())
                if (groups.isEmpty()) {
                    println("Track '$track' has no Google Groups configured.")
                } else {
                    println("Track '$track' Google Groups:")
                    groups.forEach { println("  - $it") }
                }
            }
        }

        "add-group" -> {
            if (args.size < 3) fail("Usage: add-group <track> <groupEmail>")
            val track = args[1]
            val newGroup = args[2].trim().lowercase()

            client.withEdit { editId ->
                val currentResp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track")
                val groups = parseGoogleGroups(currentResp.body())

                if (groups.contains(newGroup)) {
                    note("Group '$newGroup' is already attached to track '$track'.")
                    return@withEdit
                }

                groups.add(newGroup)
                val jsonBody = """{"googleGroups":[${groups.joinToString(",") { "\"$it\"" }}]}"""
                val updateResp = client.request("PUT", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track", jsonBody)
                if (updateResp.statusCode() !in 200..299) {
                    fail("Failed to update testers for track '$track': ${updateResp.body()}")
                }

                note("Added group '$newGroup' to track '$track'.")
                client.commitEdit(editId)
            }
        }

        "remove-group" -> {
            if (args.size < 3) fail("Usage: remove-group <track> <groupEmail>")
            val track = args[1]
            val groupToRemove = args[2].trim().lowercase()

            client.withEdit { editId ->
                val currentResp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track")
                val groups = parseGoogleGroups(currentResp.body())

                if (!groups.contains(groupToRemove)) {
                    note("Group '$groupToRemove' is not present in track '$track'.")
                    return@withEdit
                }

                groups.remove(groupToRemove)
                val jsonBody = """{"googleGroups":[${groups.joinToString(",") { "\"$it\"" }}]}"""
                val updateResp = client.request("PUT", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track", jsonBody)
                if (updateResp.statusCode() !in 200..299) {
                    fail("Failed to update testers for track '$track': ${updateResp.body()}")
                }

                note("Removed group '$groupToRemove' from track '$track'.")
                client.commitEdit(editId)
            }
        }

        "sync-groups" -> {
            if (args.size < 3) fail("Usage: sync-groups <track> <groupsFile>")
            val track = args[1]
            val file = File(args[2])
            if (!file.exists()) fail("File not found: ${file.absolutePath}")

            val targetGroups = file.readLines()
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .distinct()

            client.withEdit { editId ->
                val jsonBody = """{"googleGroups":[${targetGroups.joinToString(",") { "\"$it\"" }}]}"""
                val updateResp = client.request("PUT", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/testers/$track", jsonBody)
                if (updateResp.statusCode() !in 200..299) {
                    fail("Failed to sync testers for track '$track': ${updateResp.body()}")
                }
                note("Synchronized ${targetGroups.size} group(s) to track '$track': ${targetGroups.joinToString(", ")}")
                client.commitEdit(editId)
            }
        }

        "promote" -> {
            if (args.size < 3) fail("Usage: promote <fromTrack> <toTrack>")
            val fromTrack = args[1]
            val toTrack = args[2]

            client.withEdit { editId ->
                val sourceResp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/tracks/$fromTrack")
                if (sourceResp.statusCode() !in 200..299) {
                    fail("Failed to fetch source track '$fromTrack': ${sourceResp.body()}")
                }

                val releasesJson = extractReleasesArray(sourceResp.body())
                    ?: fail("Source track '$fromTrack' has no releases to promote.")
                val destBody = """{"track":"$toTrack","releases":$releasesJson}"""

                val updateResp = client.request("PUT", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/tracks/$toTrack", destBody)
                if (updateResp.statusCode() !in 200..299) {
                    fail("Failed to promote releases to track '$toTrack': ${updateResp.body()}")
                }

                note("Promoted releases from '$fromTrack' to '$toTrack'.")
                client.commitEdit(editId)
            }
        }

        "listings" -> {
            client.withEdit { editId ->
                val resp = client.request("GET", "$API_BASE/applications/$APP_PACKAGE/edits/$editId/listings")
                println(resp.body())
            }
        }

        "api" -> {
            if (args.size < 3) fail("Usage: api <METHOD> <path> [jsonBody]")
            val method = args[1]
            val path = args[2]
            val body = if (args.size >= 4) args.drop(3).joinToString(" ") else null

            val url = if (path.startsWith("http")) path else {
                val cleanPath = path.removePrefix("/")
                "$API_BASE/$cleanPath"
            }
            val resp = client.request(method, url, body)
            println("Status: ${resp.statusCode()}")
            println(resp.body())
        }

        else -> fail("Unknown command: '$command'. Run with --help to see available commands.")
    }
}

main(args)
