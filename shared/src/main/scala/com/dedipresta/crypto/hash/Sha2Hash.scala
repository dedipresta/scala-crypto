package com.dedipresta.crypto.hash

import java.lang.{Long => JLong}
import java.nio.ByteBuffer

trait Sha2Hash extends Hash {

  protected val Padding: Byte = Integer.parseInt("10000000", 2).toByte

  /**
    * Compute the size of the padding
    *
    * @param wordBytes The size of the word in bytes
    * @param remainingBytesOnLastBlock The number of bytes from the last incomplete block if any
    * @param messageSizeBytes The number of bytes used to store the message length
    * @return The number of bytes to allocate
    */
  protected def byteAndZeroFillPaddingSize(wordBytes: Int, remainingBytesOnLastBlock: Int, messageSizeBytes: Int): Int = {

    // 1 byte + k-0 fill until it remains only 64 bits to set the message length
    // build an extra block if current block size does not contain at least reservedBlocksPostPadding free bytes

    val reservedBlocksPostPadding = wordBytes - messageSizeBytes - 1

    1 + {
      if (remainingBytesOnLastBlock <= reservedBlocksPostPadding) {
        reservedBlocksPostPadding - remainingBytesOnLastBlock
      } else {
        wordBytes + reservedBlocksPostPadding - remainingBytesOnLastBlock
      }
    }
  }

  /**
    * Transform the message in two arrays of bytes
    * - first array contains complete blocks
    * - second array contains 1 or 2 blocks
    *   - the bytes from the last incomplete block
    *   - the fill padding (1 byte + 0-fill)
    *   - the 8-bytes for the message size
    *
    * Second array is not concatenated to the first
    * one because the array size could exceed the
    * allowed Array size that is Int.MaxValue - x
    * with x >= 1 but being platform specific
    * So, it ensures the ability to process an input
    * array provided by the user without crashing with a
    * java.lang.OutOfMemoryError
    *
    * @param message The message to hash
    * @param wordBytes The number of bytes in a word
    * @param arrayFromBytes The function to get an the given type from bytes
    * @return a tuple of int arrays
    */
  @specialized(Int, Long)
  protected def buildWords[T](message: Array[Byte], wordBytes: Int, arrayFromBytes: Array[Byte] => Array[T]): (Array[T], Array[T]) = {

    val messageSizeBytes          = JLong.BYTES
    val nbCompleteBlocks          = message.length / wordBytes
    val remainingBytesOnLastBlock = message.length % wordBytes
    val completeBlockBytes        = nbCompleteBlocks * wordBytes
    val byteAndZeroFillPadding    = byteAndZeroFillPaddingSize(wordBytes, remainingBytesOnLastBlock, messageSizeBytes)

    // initialize all words

    val completeBlocks = Array.ofDim[Byte](completeBlockBytes)
    System.arraycopy(message, 0, completeBlocks, 0, completeBlockBytes)
    val completeBlocksLongs    = arrayFromBytes(completeBlocks)
    val endBlockAndPaddingSize = remainingBytesOnLastBlock + byteAndZeroFillPadding + messageSizeBytes

    val endBlockAndPadding = Array.ofDim[Byte](endBlockAndPaddingSize)
    System.arraycopy(message, completeBlockBytes, endBlockAndPadding, 0, remainingBytesOnLastBlock)

    // write 1-byte
    endBlockAndPadding(remainingBytesOnLastBlock) = Padding
    // skip padBytes many bytes (they are already 0)

    // write 8-byte integer describing the original message length
    ByteBuffer
      .wrap(endBlockAndPadding, remainingBytesOnLastBlock + byteAndZeroFillPadding, messageSizeBytes)
      .putLong(message.length.toLong * 8)

    val paddedEndLongs = arrayFromBytes(endBlockAndPadding)

    (completeBlocksLongs, paddedEndLongs)
  }

}
