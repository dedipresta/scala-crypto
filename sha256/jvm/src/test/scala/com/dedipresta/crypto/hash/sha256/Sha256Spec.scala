package com.dedipresta.crypto.hash.sha256

import java.security.MessageDigest

import org.scalactic.anyvals.PosInt
import org.scalatest.PrivateMethodTester
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha256Spec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks with PrivateMethodTester {

  val nbTests = PosInt(1 * 1000 * 1000)

  implicit override val generatorDrivenConfig =
    PropertyCheckConfiguration(minSuccessful = nbTests, workers = PosInt(10))

  def defaultSha256(bytes: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.digest(bytes)
  }

  "Sha256" should s"generate the same hash than MessageDigest (running on ${nbTests.value} random cases)" in {

    forAll { bytes: Array[Byte] => Sha256.hash(bytes) should equal(defaultSha256(bytes)) }

  }

  "Sha256.pad" should "pad to align blocks to 512 bits/ 64 bytes" in {

    val pad = PrivateMethod[Array[Byte]](Symbol("pad"))
    forAll { bytes: Array[Byte] => ((Sha256 invokePrivate pad(bytes)).length % 64) shouldBe 0 }

  }
}
