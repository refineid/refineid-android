package fi.refineid.android.core

import android.os.Handler
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/**
 * Reads one value on the thread that owns the card session and answers
 * on Main; [read] sees the session, or null when none is open. The read runs only while [isCurrent] holds, and a value
 * read for a session that ended meanwhile goes to [discard] and is
 * answered as null, as is a read the executor refuses.
 */
internal fun <S : Any, T : Any> readOnOwnerThread(
    executor: ExecutorService,
    mainHandler: Handler,
    isCurrent: () -> Boolean,
    session: () -> S?,
    discard: (T) -> Unit,
    onResult: (T?) -> Unit,
    read: (S?) -> T?,
) {
    if (!isCurrent()) {
        onResult(null)
        return
    }
    try {
        executor.execute {
            val value =
                if (isCurrent()) {
                    try {
                        read(session())
                    } catch (_: IllegalStateException) {
                        null
                    }
                } else {
                    null
                }
            mainHandler.post {
                if (isCurrent()) {
                    onResult(value)
                } else {
                    value?.let(discard)
                    onResult(null)
                }
            }
        }
    } catch (_: RejectedExecutionException) {
        onResult(null)
    }
}
