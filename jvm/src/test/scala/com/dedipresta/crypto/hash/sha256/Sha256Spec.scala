package com.dedipresta.crypto.hash.sha256

import java.nio.ByteBuffer
import java.security.MessageDigest

import org.scalatest.PrivateMethodTester
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha256Spec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks with PrivateMethodTester {

  def defaultSha256(bytes: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.digest(bytes)
  }

  ignore should s"build a hash from an array of bytes of size Int.MaxValue - 2" in {
    val bytes = Array.ofDim[Byte](Int.MaxValue - 2)
    Sha256.hash(bytes) should equal(defaultSha256(bytes))
  }

  "Sha256.buildInts" should "pad to align blocks to 512 bits/ 64 bytes" in {

    def toIntArray(bytes: Array[Byte]): Array[Int] = {
      val buffer = ByteBuffer.wrap(bytes)
      val result = Array.ofDim[Int](bytes.length / Integer.BYTES)
      result.indices.foreach(i => result(i) = buffer.getInt())
      result
    }

    val buildWords = PrivateMethod[(Array[Int], Array[Int])](Symbol("buildWords"))
    forAll { bytes: Array[Byte] =>
      val (first, second) = Sha256 invokePrivate buildWords(bytes, 64, toIntArray _)
      first.length  % 16 shouldBe 0 // 16 ints = 64 bytes
      second.length % 16 shouldBe 0
      val Array(f, s) = second.takeRight(2)
      val size = ByteBuffer
        .allocate(8)
        .putInt(f)
        .putInt(s)
        .getLong(0)

      size shouldBe (bytes.length * 8)
    }
  }
}
