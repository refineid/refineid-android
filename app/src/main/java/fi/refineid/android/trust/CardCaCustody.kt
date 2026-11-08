// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.trust

import fi.refineid.android.core.CardCaFile
import fi.refineid.android.core.CardCaReadAnswer
import fi.refineid.android.core.NativeCardCa

/**
 * What a card session asks of the CA certificate cache around a signature:
 * whether the cache already holds the signer's chain, so the card need not
 * be asked for it, and to admit what the card supplied when it was asked.
 */
internal interface CardCaCustody {
    /** [leafCertificate] is borrowed. */
    fun holdsChainFor(leafCertificate: ByteArray): Boolean

    /** Admits the certificates the reads behind [answers] returned. */
    fun admitCardRead(answers: List<CardCaReadAnswer>)

    companion object {
        /** No cache: the card is never asked. */
        val NONE: CardCaCustody =
            object : CardCaCustody {
                override fun holdsChainFor(leafCertificate: ByteArray): Boolean = true

                override fun admitCardRead(answers: List<CardCaReadAnswer>) = Unit
            }
    }
}

/** [CardCaCustody] over the application's [CaCertificateStore]. */
internal class StoreCardCaCustody(
    private val store: CaCertificateStore,
) : CardCaCustody {
    override fun holdsChainFor(leafCertificate: ByteArray): Boolean = store.hasChainFor(leafCertificate)

    override fun admitCardRead(answers: List<CardCaReadAnswer>) {
        fun wasRead(file: CardCaFile): Boolean = answers.any { answer -> answer.file == file && answer.isRead }
        val root = if (wasRead(CardCaFile.ROOT_CA)) NativeCardCa.readRootCaCertificate() else null
        val issuing = if (wasRead(CardCaFile.ISSUING_CA)) NativeCardCa.readIntermediateCaCertificate() else null
        store.admitCardChain(rootDer = root, issuingDer = issuing)
    }
}
