package dtls.dto

import java.nio.ByteBuffer

import dtls.util.codec.Codec

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
case class StringMessage(msg: String) extends DTLSMessage
object StringMessage {

  val PacketID: Byte = 0xF1.toByte

  implicit val codec: Codec[StringMessage] = new Codec[StringMessage] {

    override def encode(obj: StringMessage): ByteBuffer = {
      val length  = obj.msg.length
      val bb      = ByteBuffer.allocate(length + java.lang.Short.BYTES + java.lang.Byte.BYTES)

      bb.put(PacketID)
      bb.putShort(length.toShort)
      bb.put(obj.msg.getBytes())
      bb.flip()
      bb
    }

    override def decode(bb: ByteBuffer): StringMessage = {
      val magic  = bb.get(0)      // should be 0xF1
      val length = bb.getShort(1)

      val buffer = Array.ofDim[Byte](length)
      bb.position(3)
      bb.get(buffer, 0, length)

      StringMessage(new String(buffer))
    }
  }

}
