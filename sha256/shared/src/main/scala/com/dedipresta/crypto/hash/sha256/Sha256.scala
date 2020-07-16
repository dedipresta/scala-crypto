package com.dedipresta.crypto.hash.sha256

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

object Sha256 {

  // format: off
  private val K = Array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  )
  // format: on

  private val H0 = Array(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

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
    val words = toIntArray(pad(message))

    val N = words.length / 16

    // enumerate all blocks (each containing 16 words)
    var i = 0
    while (i < N) {

      // initialize W from the block's words
      System.arraycopy(words, i * 16, W, 0, 16)

      (16 until W.length).foreach(t => W(t) = smallSig1(W(t - 2)) + W(t - 7) + smallSig0(W(t - 15)) + W(t - 16))

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
    * Hashes the given message with SHA-256
    * and returns the computed hash in a
    * bytes array
    *
    * @param message The string to hash
    * @return The resulting bytes array
    */
  def hash(message: String): Array[Byte] = hash(message.getBytes(StandardCharsets.UTF_8))

  /**
    * Hashes the given message with SHA-256 and
    * returns the computed hash in a 64 characters
    * length hexadecimal string
    *
    * @param message The message to hash
    * @return The hexadecimal string hash
    */
  def hashString(message: String): String = hex(hash(message))

  /**
    * Hashes the given message with SHA-256 and
    * returns the computed hash in a 64 characters
    * length hexadecimal string
    *
    * @param message The message to hash
    * @return The hexadecimal string hash
    */
  def hashString(message: Array[Byte]): String = hex(hash(message))

  private def hex(bytes: Array[Byte]): String = {
    val sb = new StringBuilder
    bytes.foreach(byte => sb.append("%02x".format(byte & 0xff)))
    sb.toString
  }

  private val padding: Byte     = Integer.parseInt("10000000", 2).toByte
  private val paddingBlockBits  = 512
  private val paddingBlockBytes = paddingBlockBits / 8

  /**
    * Pads the given message
    * The length has to be a multiple of 512 bits (64 bytes)
    * Includes a 1-bit, k 8-bits, and the message
    * length as a 64-bit integer
    *
    * @param message The message to pad
    * @return A new array with the padded message bytes
    */
  private def pad(message: Array[Byte]): Array[Byte] = {

    // new message length: original + 1-bit and padding + 8-byte length
    val newMessageLength       = message.length + 1 + 8
    val padBytes               = (paddingBlockBytes - newMessageLength % paddingBlockBytes) % paddingBlockBytes
    val newPaddedMessageLength = newMessageLength + padBytes

    // copy message to extended array
    val paddedMessage = Array.ofDim[Byte](newPaddedMessageLength)
    System.arraycopy(message, 0, paddedMessage, 0, message.length)

    // write 1-bit
    paddedMessage(message.length) = padding
    // skip padBytes many bytes (they are already 0)

    // write 8-byte integer describing the original message length
    val lenPos = message.length + 1 + padBytes
    ByteBuffer.wrap(paddedMessage, lenPos, 8).putLong(message.length.toLong * 8)
    paddedMessage
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
