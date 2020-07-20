package com.dedipresta.crypto.hash.sha256

import java.nio.charset.StandardCharsets

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha256CommonSpec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks {

  "Sha256" should s"generate a valid hash for an empty string" in {
    hash("") shouldBe "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }

  it should "generate a valid hash for a simple string" in {
    hash("Scala.js!") shouldBe "25ed477793a2663fc5173a24f1a1f0750d5bd7f577dabee09452d82d3caff0e2"
  }

  it should "generate a valid hash for 1 000 000 chars string" in {
    hash("0" * (1 * 1000 * 1000)) shouldBe "ba4b3010e2d91c08bd1987998d82b89b52ae1bdbc360f066607c7ee5a9c5830e"
  }

  it should "generate a valid hash for a string containing the 65536 first characters" in {
    hash((0 to 65535).map(_.toChar).mkString("")) shouldBe "b6b8dab9fc3e83eba31a936a7e15b4016cf2165b6973636cbb81ded0c6a23bb8"
  }

  it should "generate a valid hash for an Array of bytes" in {
    hash((0 to 255).map(_.toByte).toArray) shouldBe "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"
  }

  it should "generate the same byte array hash for a string and its given utf8 bytes" in {
    forAll { s: String => hash(s) shouldBe hash(s.getBytes(StandardCharsets.UTF_8)) }
  }

  it should "generate the same hexadecimal string hash for a string and its given utf8 bytes" in {
    forAll { s: String => Sha256.hashString(s) shouldBe Sha256.hashString(s.getBytes(StandardCharsets.UTF_8)) }
  }

  it should "generate an lower cased hexadecimal string of size 64" in {
    forAll { s: String => Sha256.hashString(s) should fullyMatch regex "[a-f0-9]{64}" }
  }

  def hash(bytes: Array[Byte]): String = hex(Sha256.hash(bytes))
  def hash(s: String): String          = hash(s.getBytes(StandardCharsets.UTF_8))

  def hex(bytes: Array[Byte]): String = {
    val sb = new StringBuilder
    bytes.foreach(byte => sb.append("%02x".format(byte & 0xff)))
    sb.toString
  }

}
