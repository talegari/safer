#' @title Encrypt a string
#'
#' @description \code{encrypt_string} encrypts a string as a string or a raw
#'   vector and \code{decrypt_string} decrypts the encrypted string or a raw
#'   vector (encrypted using \code{encrypt_string})
#'
#' @param string A string(character vector of length 1) without embedded NULL to
#'   be encrypted or a raw vector.
#' @param key For symmetric encryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric encryption, both 'key' (private key of the encrypter) and 'pkey'
#'   (public key of the decrypter) should be raw objects.
#' @param pkey See 'key'
#' @param ascii (flag) When TRUE (default), the output is a string after base64
#'   encoding. Else, the output is a raw vector.
#'
#' @return An encrypted string or a raw vector.
#'
#' @examples
#' # symmetric case:
#' temp <- encrypt_string("hello, how are you", key = "secret")
#' all(
#'   is.character(temp)
#'   , decrypt_string(temp, "secret") == "hello, how are you"
#'   , class(try(decrypt_string(temp, "nopass"), silent = TRUE)) == "try-error"
#'   )
#'
#' # string encoded as raw
#' res <- encrypt_string("tatvamasi", ascii = FALSE)
#' res
#'
#' isTRUE(identical(decrypt_string(res), "tatvamasi"))
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' temp  <- encrypt_string("hello asymmetric", alice$private_key, bob$public_key)
#' temp2 <- decrypt_string(temp, bob$private_key, alice$public_key)
#' identical("hello asymmetric", temp2)
#'
#' @export

encrypt_string <- function(string
                           , key    = "pass"
                           , pkey   = NULL
                           , ascii  = TRUE
                           ){

  assert_that(is.string(string))

  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }

  assert_that(is.flag(ascii))

  if(is.string(key)){
    keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
    if(is.error(keyAsRaw)){
      stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
    }
  } else {
    keyAsRaw <- key
  }

  stringAsRaw <- try(charToRaw(string), silent = TRUE)
  if(is.error(stringAsRaw)){
    stop("Unable to convert string to raw. Ensure string does not have a embedded NULL")
  }


  if(method == "symmetric"){
    string_enc_raw <- data_encrypt(stringAsRaw
                                   , keyAsRaw
                                   , hash(charToRaw("nounce"), size = 24)
                                   )
  } else {
    string_enc_raw <- auth_encrypt(stringAsRaw
                                   , key
                                   , pkey
                                   , hash(charToRaw("nounce"), size = 24)
                                   )
  }

  attr(string_enc_raw, "nonce") <- NULL

  if(ascii){
    return( base64encode(string_enc_raw) )
  } else {
    return( string_enc_raw )
  }
}

#' @title Decrypt a string or a raw vector
#'
#' @description \code{encrypt_string} encrypts a string as a string or a raw vector and
#'   \code{decrypt_string} decrypts the encrypted string or a raw vector (encrypted using
#'   \code{encrypt_string})
#'
#' @param string A string(character vector of length 1) without embedded NULL to
#'   be encrypted. or a raw vector.
#' @param key For symmetric decryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric decryption, both 'key' (private key of the decrypter) and 'pkey'
#'   (public key of the encrypter) should be raw objects.
#' @param pkey See 'key'
#'
#' @return decrypted string
#'
#' @examples
#' # symmetric case:
#' temp <- encrypt_string("hello, how are you", key = "secret")
#' all(
#'   is.character(temp)
#'   , decrypt_string(temp, "secret") == "hello, how are you"
#'   , class(try(decrypt_string(temp, "nopass"), silent = TRUE)) == "try-error"
#'   )
#'
#' # string encoded as raw
#' res <- encrypt_string("tatvamasi", ascii = FALSE)
#' res
#'
#' isTRUE(identical(decrypt_string(res), "tatvamasi"))
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' temp  <- encrypt_string("hello asymmetric", alice$private_key, bob$public_key)
#' temp2 <- decrypt_string(temp, bob$private_key, alice$public_key)
#' identical("hello asymmetric", temp2)
#'
#' @export

decrypt_string <- function(string
                           , key = "pass"
                           , pkey = NULL
                           ){

  assert_that(is.string(string) || is.raw(string))

  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }

  if(is.string(string)){
    stringAsRaw <- try(base64decode(string), silent = TRUE)
    if(is.error(stringAsRaw)){
      stop("Unable to decode string. Ensure that the input was generated by 'encrypt_string' function")
    }
  } else {
    stringAsRaw <- string
  }

  if(is.string(key)){
    keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
    if(is.error(keyAsRaw)){
      stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
    }
  } else {
    keyAsRaw <- key
  }

  if(method == "symmetric"){
    string_dec_raw <- try(data_decrypt(stringAsRaw
                                       , keyAsRaw
                                       , hash(charToRaw("nounce"), size = 24))
                          , silent = TRUE)

  } else {
    string_dec_raw <- try(auth_decrypt(stringAsRaw
                                       , key
                                       , pkey
                                       , hash(charToRaw("nounce"), size = 24))
                          , silent = FALSE)
  }

  if(is.error(string_dec_raw)){
    stop("Unable to decrypt. Ensure that the input was generated by 'encrypt_string'.")
  }
  return(rawToChar(string_dec_raw))
}
