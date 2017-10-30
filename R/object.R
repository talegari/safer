#' @title Encrypt a object
#'
#' @description \code{encrypt_object} encrypts a object as a raw object or a
#'   string and \code{decrypt_object} decrypts a raw object or a
#'   string(encrypted by \code{encrypt_object})
#'
#' @param object Object to be encrypted
#' @param ascii \code{TRUE} if the object is to be encrypted as a string.
#'   Default is \code{FALSE}
#' @param key For symmetric encryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric encryption, both 'key' (private key of the encrypter) and 'pkey'
#'   (public key of the decrypter) should be raw objects.
#' @param pkey See 'key'
#'
#' @return A raw object if \code{ascii} is \code{FALSE}. A string if
#'   \code{ascii} is \code{TRUE}.
#'
#' @examples
#' # symmetric case:
#' temp <- encrypt_object(1:3)
#' all(
#'   is.raw(temp)
#'   , decrypt_object(temp) == 1:3)
#'
#' temp <- encrypt_object(iris, ascii = TRUE)
#' all(
#'   is.character(temp)
#'   , decrypt_object(temp) == iris
#'   , identical(decrypt_object(temp), iris))
#' rm(temp)
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' temp  <- encrypt_object(1:10, alice$private_key, bob$public_key)
#' temp2 <- decrypt_object(temp, bob$private_key, alice$public_key)
#' identical(1:10, temp2)
#'
#' @export
#'
encrypt_object  <- function(object
                            , key    = "pass"
                            , pkey   = NULL
                            , ascii  = FALSE){

  assert_that(!missing(object))
  assert_that(is.flag(ascii))
  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }

  raw_object <- try(serialize(object, NULL), silent = TRUE)
  if(is.error(raw_object)){
    stop("Unable to serialize the object")
  }
  if(is.string(key)){
    keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  } else {
    keyAsRaw <- key
  }

  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  if(method == "symmetric"){
    object_enc_raw <- data_encrypt(raw_object
                                   , keyAsRaw
                                   , hash(charToRaw("nounce"), size = 24)
                                   )
  } else {
    object_enc_raw <- auth_encrypt(raw_object
                                   , key
                                   , pkey
                                   , hash(charToRaw("nounce"), size = 24))
  }

  attributes(object_enc_raw) <- NULL
  if(ascii){
    return(base64encode(object_enc_raw))
  } else {
    return(object_enc_raw)
  }
}

#' @title Decrypt a object
#'
#' @description \code{encrypt_object} encrypts a R object as a raw object or a
#'   string and \code{decrypt_object} decrypts a raw object or a
#'   string(encrypted by \code{encrypt_object})
#'
#' @param object Object to be decrypted
#' @param key For symmetric decryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric decryption, both 'key' (private key of the decrypter) and 'pkey'
#'   (public key of the encrypter) should be raw objects.
#' @param pkey See 'key'
#'
#' @return A raw object if \code{ascii} is \code{FALSE}. A string if
#'   \code{ascii} is \code{TRUE}.
#'
#' @examples
#' # symmetric case:
#' temp <- encrypt_object(1:3)
#' all(
#'   is.raw(temp)
#'   , decrypt_object(temp) == 1:3)
#'
#' temp <- encrypt_object(iris, ascii = TRUE)
#' all(
#'   is.character(temp)
#'   , decrypt_object(temp) == iris
#'   , identical(decrypt_object(temp), iris))
#' rm(temp)
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' temp  <- encrypt_object(1:10, alice$private_key, bob$public_key)
#' temp2 <- decrypt_object(temp, bob$private_key, alice$public_key)
#' identical(1:10, temp2)
#'
#' @export
#'
decrypt_object  <- function(object
                            , key    = "pass"
                            , pkey   = NULL){

  assert_that(!missing(object))
  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }
  assert_that(is.raw(object) || is.string(object))

  if(is.string(object)){
    object <- try(base64decode(object), silent = TRUE)
    if(is.error(object)){
      stop("Unable to Decrypt. Ensure that input was the result of 'encypt_object' function with 'ascii' set to TRUE.")
    }
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
    object_dec_raw <- try(data_decrypt(object
                                       , keyAsRaw
                                       , hash(charToRaw("nounce"), size = 24))
                          , silent = TRUE)
  } else {
    object_dec_raw <- try(auth_decrypt(object
                                       , key
                                       , pkey
                                       , hash(charToRaw("nounce"), size = 24))
                          , silent = TRUE)
  }

  if(is.error(object_dec_raw)){
    stop("Unable to Decrypt. Ensure that input was generated by 'encypt_object' function.")
  }
  return(unserialize(object_dec_raw))
}
