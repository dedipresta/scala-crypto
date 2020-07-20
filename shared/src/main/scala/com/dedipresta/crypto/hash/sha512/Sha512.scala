package com.dedipresta.crypto.hash.sha512

import java.lang.{Byte => JByte}
import java.lang.{Long => JLong}
import java.nio.ByteBuffer

import com.dedipresta.crypto.hash.Sha2Hash

object Sha512 extends Sha2Hash {

  // format: off
  private val K: Array[Long] = Array(
    0x428A2F98D728AE22L, 0x7137449123EF65CDL, 0xB5C0FBCFEC4D3B2FL, 0xE9B5DBA58189DBBCL,
    0x3956C25BF348B538L, 0x59F111F1B605D019L, 0x923F82A4AF194F9BL, 0xAB1C5ED5DA6D8118L,
    0xD807AA98A3030242L, 0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
    0x72BE5D74F27B896FL, 0x80DEB1FE3B1696B1L, 0x9BDC06A725C71235L, 0xC19BF174CF692694L,
    0xE49B69C19EF14AD2L, 0xEFBE4786384F25E3L, 0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L,
    0x2DE92C6F592B0275L, 0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
    0x983E5152EE66DFABL, 0xA831C66D2DB43210L, 0xB00327C898FB213FL, 0xBF597FC7BEEF0EE4L,
    0xC6E00BF33DA88FC2L, 0xD5A79147930AA725L, 0x06CA6351E003826FL, 0x142929670A0E6E70L,
    0x27B70A8546D22FFCL, 0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
    0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, 0x81C2C92E47EDAEE6L, 0x92722C851482353BL,
    0xA2BFE8A14CF10364L, 0xA81A664BBC423001L, 0xC24B8B70D0F89791L, 0xC76C51A30654BE30L,
    0xD192E819D6EF5218L, 0xD69906245565A910L, 0xF40E35855771202AL, 0x106AA07032BBD1B8L,
    0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L, 0x34B0BCB5E19B48A8L,
    0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL, 0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L,
    0x748F82EE5DEFB2FCL, 0x78A5636F43172F60L, 0x84C87814A1F0AB72L, 0x8CC702081A6439ECL,
    0x90BEFFFA23631E28L, 0xA4506CEBDE82BDE9L, 0xBEF9A3F7B2C67915L, 0xC67178F2E372532BL,
    0xCA273ECEEA26619CL, 0xD186B8C721C0C207L, 0xEADA7DD6CDE0EB1EL, 0xF57D4F7FEE6ED178L,
    0x06F067AA72176FBAL, 0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
    0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL, 0x431D67C49C100D4CL,
    0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL, 0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
  )
  // format: on

  // format: off
  private val H0 = Array(
    0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL, 0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
    0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL, 0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
  )
  // format: on

  private val WordBits  = 1024
  private val WordBytes = WordBits / JByte.SIZE
  private val WordLongs = WordBytes / JLong.BYTES

  /**
    * Hashes the given message with SHA-512
    * and returns the computed hash in a
    * bytes array
    *
    * @param message The bytes array to hash
    * @return The resulting bytes array
    */
  def hash(message: Array[Byte]): Array[Byte] = {

    // working arrays
    val W    = Array.ofDim[Long](80)
    val H    = Array.ofDim[Long](8)
    val TEMP = Array.ofDim[Long](8)

    // let H = H0
    System.arraycopy(H0, 0, H, 0, H0.length)

    // initialize all words
    val (completeBlocks, endBlockAndPadding) = buildWords(message, WordBytes, toLongArray)
    val completeBlocksWords                  = completeBlocks.length / WordLongs
    val endBlockAndPaddingWords              = endBlockAndPadding.length / WordLongs
    val totalWords                           = completeBlocksWords + endBlockAndPaddingWords

    // enumerate all blocks (each containing 16 words)
    var i = 0
    while (i < totalWords) {

      // initialize W from the block's words
      if (i < completeBlocksWords) {
        System.arraycopy(completeBlocks, i * WordLongs, W, 0, WordLongs)
      } else {
        System.arraycopy(endBlockAndPadding, (i - completeBlocksWords) * WordLongs, W, 0, WordLongs)
      }

      (WordLongs until W.length).foreach(t => W(t) = smallSig1(W(t - 2)) + W(t - 7) + smallSig0(W(t - 15)) + W(t - 16))

      // let TEMP = H
      System.arraycopy(H, 0, TEMP, 0, H.length)

      // operate on TEMP
      W.indices.foreach { t =>
        val t1 = TEMP(7) + bigSig1(TEMP(4)) + ch(TEMP(4), TEMP(5), TEMP(6)) + K(t) + W(t)
        val t2 = bigSig0(TEMP(0)) + maj(TEMP(0), TEMP(1), TEMP(2))
        System.arraycopy(TEMP, 0, TEMP, 1, TEMP.length - 1)
        TEMP(4) += t1
        TEMP(0) = t1 + t2
      }

      // add values in TEMP to values in H
      H.indices.foreach(t => H(t) += TEMP(t))

      i += 1
    }

    toByteArray(H)
  }

  /**
    * Converts the given byte array into an array
    * of integers via big-endian conversion
    *
    * @param bytes The source array
    * @return The converted array
    */
  private def toLongArray(bytes: Array[Byte]): Array[Long] = {
    val buffer = ByteBuffer.wrap(bytes)
    val result = Array.ofDim[Long](bytes.length / JLong.BYTES)
    result.indices.foreach(i => result(i) = buffer.getLong())
    result
  }

  /**
    * Converts the given array of integers into a
    * byte array via big-endian conversion
    *
    * @param longs The source array
    * @return The converted array
    */
  private def toByteArray(longs: Array[Long]): Array[Byte] = {
    val buffer = ByteBuffer.allocate(longs.length * JLong.BYTES)
    longs.indices.foreach(i => buffer.putLong(longs(i)))
    buffer.array()
  }

  private def ch(x: Long, y: Long, z: Long) = (x & y) | ((~x) & z)

  private def maj(x: Long, y: Long, z: Long) = (x & y) | (x & z) | (y & z)

  private def bigSig0(x: Long) = JLong.rotateRight(x, 28) ^ JLong.rotateRight(x, 34) ^ JLong.rotateRight(x, 39)

  private def bigSig1(x: Long) = JLong.rotateRight(x, 14) ^ JLong.rotateRight(x, 18) ^ JLong.rotateRight(x, 41)

  private def smallSig0(x: Long) = JLong.rotateRight(x, 1) ^ JLong.rotateRight(x, 8) ^ (x >>> 7)

  private def smallSig1(x: Long) = JLong.rotateRight(x, 19) ^ JLong.rotateRight(x, 61) ^ (x >>> 6)

}
