package com.dedipresta.crypto.hash

import java.nio.charset.StandardCharsets

trait Hash {

  /**
    * Hashes the given message with requested
    * algorithm and returns the computed hash
    * in an array of bytes
    *
    * @param message The bytes array to hash
    * @return The resulting bytes array
    */
  def hash(message: Array[Byte]): Array[Byte]

  /**
    * Hashes the given message with requested
    * algorithm and returns the computed hash
    * in an array of bytes
    *
    * @param message The string to hash
    * @return The resulting bytes array
    */
  def hash(message: String): Array[Byte] = hash(message.getBytes(StandardCharsets.UTF_8))

  /**
    * Hashes the given message with requested
    * algorithm and returns the computed hash
    * in a 64 characters length hexadecimal string
    *
    * @param message The message to hash
    * @return The hexadecimal string hash
    */
  def hashString(message: String): String = hex(hash(message))

  /**
    * Hashes the given message with requested
    * algorithm and returns the computed hash
    * in a 64 characters length hexadecimal string
    *
    * @param message The message to hash
    * @return The hexadecimal string hash
    */
  def hashString(message: Array[Byte]): String = hex(hash(message))

  /**
    * Transform an array of bytes
    * to an hexadecimal string
    *
    * @param bytes  The array to transform
    * @return a lower case hexadecimal string
    */
  protected def hex(bytes: Array[Byte]): String = {
    val sb = new StringBuilder
    bytes.foreach(byte => sb.append("%02x".format(byte & 0xff)))
    sb.toString
  }

}
