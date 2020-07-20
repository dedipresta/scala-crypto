package com.dedipresta.crypto.hash.sha512

import java.nio.charset.StandardCharsets

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Sha512CommonSpec extends AnyFlatSpec with Matchers with ScalaCheckDrivenPropertyChecks {

  "Sha512" should s"generate a valid hash for an empty string" in {
    hash("") shouldBe "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  }

  it should "generate a valid hash for a simple string" in {
    hash("Scala.js!") shouldBe "f3021ecec52886d77769e7cff0b09d24df75466c76650c9e7579814e6bca49de9acb8bb64c2007e20b4aeb549ff8e5bc705ecf011d050ffc233ecf17f6f66200"
  }

  it should "generate a valid hash for 1 000 000 chars string" in {
    hash("0" * (1 * 1000 * 1000)) shouldBe "8b38d52d0ff170a4d1bab43ca708a29dc42e80bb09d13259bbe5e0dfe5ace2aea81b131de703ebf2d5bfee14f009f89854406c00ade771f2ac161b8ecfd7ab2c"
  }

  it should "generate a valid hash for a string containing the 65536 first characters" in {
    hash((0 to 65535).map(_.toChar).mkString("")) shouldBe "5c75c799d4e62a99c8bf96e978cea81354ead1c143879ecc7736e8adfbfe4afe0484058c2d0fa920799200746ea692fd7bd86ebe880ed2d657ea045d1b9089c7"
  }

  it should "generate a valid hash for an Array of bytes" in {
    hash((0 to 255).map(_.toByte).toArray) shouldBe "1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d"
  }

  it should "generate the same byte array hash for a string and its given utf8 bytes" in {
    forAll { s: String => hash(s) shouldBe hash(s.getBytes(StandardCharsets.UTF_8)) }
  }

  it should "generate the same hexadecimal string hash for a string and its given utf8 bytes" in {
    forAll { s: String => Sha512.hashString(s) shouldBe Sha512.hashString(s.getBytes(StandardCharsets.UTF_8)) }
  }

  it should "generate an lower cased hexadecimal string of size 128" in {
    forAll { s: String => Sha512.hashString(s) should fullyMatch regex "[a-f0-9]{128}" }
  }

  def hash(bytes: Array[Byte]): String = hex(Sha512.hash(bytes))
  def hash(s: String): String          = hash(s.getBytes(StandardCharsets.UTF_8))

  def hex(bytes: Array[Byte]): String = {
    val sb = new StringBuilder
    bytes.foreach(byte => sb.append("%02x".format(byte & 0xff)))
    sb.toString
  }

}
