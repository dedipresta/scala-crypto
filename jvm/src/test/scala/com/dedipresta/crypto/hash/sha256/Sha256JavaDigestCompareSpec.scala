package com.dedipresta.crypto.hash.sha256

import java.security.MessageDigest

import org.scalactic.anyvals.PosInt
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha256JavaDigestCompareSpec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks {

  val nbTests: PosInt = PosInt(100 * 1000)

  implicit override val generatorDrivenConfig: PropertyCheckConfiguration =
    PropertyCheckConfiguration(minSuccessful = nbTests, workers = PosInt(10))

  def defaultSha256(bytes: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.digest(bytes)
  }

  "Sha256" should s"generate the same hash than MessageDigest (running on ${nbTests.value} random cases)" in {
    forAll { bytes: Array[Byte] => Sha256.hash(bytes) should equal(defaultSha256(bytes)) }
  }

}
