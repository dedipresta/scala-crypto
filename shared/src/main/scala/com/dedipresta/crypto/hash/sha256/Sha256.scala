package com.dedipresta.crypto.hash.sha256

import java.lang.{Byte => JByte}
import java.nio.ByteBuffer

import com.dedipresta.crypto.hash.Sha2Hash

object Sha256 extends Sha2Hash {

  // format: off
  private val K = Array(
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
  )
  // format: on

  private val H0 = Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

  private val WordBits  = 512
  private val WordBytes = WordBits / JByte.SIZE
  private val WordInts  = WordBytes / Integer.BYTES

  /**
    * Hashes the given message with SHA-256
    * and returns the computed hash in a
    * bytes array
    *
    * @param message The bytes array to hash
    * @return The resulting bytes array
    */
  def hash(message: Array[Byte]): Array[Byte] = {

    // working arrays
    val W    = Array.ofDim[Int](64)
    val H    = Array.ofDim[Int](8)
    val TEMP = Array.ofDim[Int](8)

    // let H = H0
    System.arraycopy(H0, 0, H, 0, H0.length)

    // initialize all words
    val (completeBlocks, endBlockAndPadding) = buildWords(message, WordBytes, toIntArray)
    val completeBlocksWords                  = completeBlocks.length / WordInts
    val endBlockAndPaddingWords              = endBlockAndPadding.length / WordInts
    val totalWords                           = completeBlocksWords + endBlockAndPaddingWords

    // enumerate all blocks (each containing 16 words)
    var i = 0
    while (i < totalWords) {

      // initialize W from the block's words
      if (i < completeBlocksWords) {
        System.arraycopy(completeBlocks, i * WordInts, W, 0, WordInts)
      } else {
        System.arraycopy(endBlockAndPadding, (i - completeBlocksWords) * WordInts, W, 0, WordInts)
      }

      (WordInts until W.length).foreach(t => W(t) = smallSig1(W(t - 2)) + W(t - 7) + smallSig0(W(t - 15)) + W(t - 16))

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
  private def toIntArray(bytes: Array[Byte]): Array[Int] = {
    val buffer = ByteBuffer.wrap(bytes)
    val result = Array.ofDim[Int](bytes.length / Integer.BYTES)
    result.indices.foreach(i => result(i) = buffer.getInt())
    result
  }

  /**
    * Converts the given array of integers into a
    * byte array via big-endian conversion
    *
    * @param ints The source array
    * @return The converted array
    */
  private def toByteArray(ints: Array[Int]): Array[Byte] = {
    val buffer = ByteBuffer.allocate(ints.length * Integer.BYTES)
    ints.indices.foreach(i => buffer.putInt(ints(i)))
    buffer.array()
  }

  private def ch(x: Int, y: Int, z: Int) = (x & y) | ((~x) & z)

  private def maj(x: Int, y: Int, z: Int) = (x & y) | (x & z) | (y & z)

  private def bigSig0(x: Int) = Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13) ^ Integer.rotateRight(x, 22)

  private def bigSig1(x: Int) = Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11) ^ Integer.rotateRight(x, 25)

  private def smallSig0(x: Int) = Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3)

  private def smallSig1(x: Int) = Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10)

}
