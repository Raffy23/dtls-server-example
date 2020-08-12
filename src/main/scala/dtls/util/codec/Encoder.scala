package dtls.util.codec

import java.nio.ByteBuffer

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
trait Encoder[T] {

  def encode(obj: T): ByteBuffer

}
