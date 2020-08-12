package dtls.dto

import java.nio.ByteBuffer

import dtls.util.codec.Codec

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
case class ACKMessage(seqNum: Short) extends DTLSMessage
object ACKMessage {

  val PacketID: Byte = 0xFF.toByte

  implicit val codec: Codec[ACKMessage] = new Codec[ACKMessage] {

    override def encode(obj: ACKMessage): ByteBuffer = {
      val bb      = ByteBuffer.allocate(java.lang.Short.BYTES + java.lang.Byte.BYTES)

      bb.put(PacketID)
      bb.putShort(obj.seqNum)
      bb.flip()
      bb
    }

    override def decode(bb: ByteBuffer): ACKMessage = {
      val magic  = bb.get(0)      // should be 0xFF
      val length = bb.getShort(1)

      ACKMessage(length)
    }
  }



}
