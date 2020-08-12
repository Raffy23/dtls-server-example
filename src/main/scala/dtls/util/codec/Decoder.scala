package dtls.util.codec

import java.nio.ByteBuffer

import fs2.Chunk

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
trait Decoder[T] {

  def decode(bb: ByteBuffer): T

}
