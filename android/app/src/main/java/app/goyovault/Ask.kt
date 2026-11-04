package app.goyovault

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CompletableDeferred

/**
 * One question a flow asks in the middle (a spare key, a gate's question,
 * a preview, the other device's new password), shown as a dialog over
 * every screen. The flow suspends until the user answers; a lock answers
 * every open question with null (No).
 */
class Question(
    val title: String,
    val text: String,
    val yes: String,
    val no: String?,
    /** A secret field in the dialog (its label), or null. */
    val field: String? = null,
    /** The field takes digits only (a PIN). */
    val digits: Boolean = false,
    /** A risky yes (danger, default no). */
    val danger: Boolean = false,
) {
    val answer = CompletableDeferred<CharArray?>()
}

object Ask {
    var current: Question? by mutableStateOf(null)
        private set

    /**
     * Asks `q`: null for No (or a lock), else the field's characters (an
     * empty array without a field), which the caller wipes.
     */
    suspend fun ask(q: Question): CharArray? {
        current?.answer?.complete(null)
        current = q
        try {
            return q.answer.await()
        } finally {
            if (current === q) current = null
        }
    }

    suspend fun yes(title: String, text: String, yes: String, no: String = "취소", danger: Boolean = false): Boolean =
        ask(Question(title, text, yes, no, danger = danger)) != null

    /** Answers the open question with No (a lock). */
    fun cancel() {
        current?.answer?.complete(null)
        current = null
    }
}
