package com.dedipresta.crypto.hash.sha512

import java.security.MessageDigest

import org.scalactic.anyvals.PosInt
import org.scalatest.PrivateMethodTester
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha512JavaDigestCompareSpec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks with PrivateMethodTester {

  val nbTests = PosInt(100 * 1000)

  implicit override val generatorDrivenConfig =
    PropertyCheckConfiguration(minSuccessful = nbTests, workers = PosInt(10))

  def defaultSha512(bytes: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-512")
    digest.digest(bytes)
  }

  "Sha512" should s"generate the same hash than MessageDigest (running on ${nbTests.value} random cases)" in {
    forAll { bytes: Array[Byte] => Sha512.hash(bytes) should equal(defaultSha512(bytes)) }
  }

}
