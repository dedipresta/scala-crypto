package com.dedipresta.crypto.hash.sha512

import java.nio.ByteBuffer
import java.security.MessageDigest

import org.scalatest.PrivateMethodTester
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha512Spec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks with PrivateMethodTester {

  def defaultSha512(bytes: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-512")
    digest.digest(bytes)
  }

  "Sha512.buildLongs" should "pad to align blocks to 1024 bits/ 128 bytes" in {

    def toLongArray(bytes: Array[Byte]): Array[Long] = {
      val buffer = ByteBuffer.wrap(bytes)
      val result = Array.ofDim[Long](bytes.length / java.lang.Long.BYTES)
      result.indices.foreach(i => result(i) = buffer.getLong())
      result
    }

    val buildWords = PrivateMethod[(Array[Long], Array[Long])](Symbol("buildWords"))
    forAll { bytes: Array[Byte] =>
      val (first, second) = Sha512 invokePrivate buildWords(bytes, 128, toLongArray _)
      first.length  % 16 shouldBe 0 // 16 longs = 128 bytes
      second.length % 16 shouldBe 0
      val Array(f, s) = second.takeRight(2)
      f shouldBe 0
      s shouldBe (bytes.length * 8)
    }
  }
}
