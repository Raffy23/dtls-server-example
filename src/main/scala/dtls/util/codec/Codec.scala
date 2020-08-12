package dtls.util.codec

/**
 * Created by 
 *
 * @author Raphael Ludwig
 * @version 08.08.20
 */
trait Codec[T] extends Encoder[T] with Decoder[T] {}
