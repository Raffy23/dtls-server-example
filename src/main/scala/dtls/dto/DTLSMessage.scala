package dtls.dto

import java.nio.ByteBuffer

import dtls.util.codec.Codec

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 09.08.20
 */
trait DTLSMessage
object DTLSMessage {

  implicit val codec: Codec[DTLSMessage] = new Codec[DTLSMessage] {

    override def encode(obj: DTLSMessage): ByteBuffer = {
      obj match {
        case m: ACKMessage => ACKMessage.codec.encode(m)
        case m: StringMessage => StringMessage.codec.encode(m)
      }
    }

    override def decode(bb: ByteBuffer): DTLSMessage = {
      bb.get(0) match {
        case ACKMessage.PacketID => ACKMessage.codec.decode(bb)
        case StringMessage.PacketID =>  StringMessage.codec.decode(bb)
      }
    }
  }

}
