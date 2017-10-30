#' @title Save an object to a connection(or a file)
#' @description \code{save_object} encrypts a R object to raw or text connection
#'   or a file. \code{retrieve_object} decrypts a raw or a text connection or a
#'   file (encrypted by \code{save_object}). Note that \code{retrieve_object}
#'   returns the object.
#'
#' @param object A R object to be encrypted
#' @param key For symmetric encryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric encryption, both 'key' (private key of the encrypter) and 'pkey'
#'   (public key of the decrypter) should be raw objects.
#' @param pkey See 'key'
#' @param ascii TRUE, if the encrypted output is a string(written to the text
#'   connection). FALSE, if the encrypted output is a raw object(written to the
#'   raw connection)
#' @param conn A connection or a file where the encrypted content is written. If
#'   \code{ascii} is TRUE, an encrypted text is written to the connection. Else,
#'   when \code{ascii} is FALSE(default), a raw object is written to the
#'   connection
#'
#' @return An invisible TRUE
#'
#' @examples
#' # symmetric case:
#' all(
#'   save_object(iris, conn = "iris_safer.bin")
#'   , identical(retrieve_object(conn = "iris_safer.bin"), iris)
#'   , unlink("iris_safer.bin") == 0
#' )
#'
#' all(
#'   save_object(iris, conn = "iris_safer_2.txt", ascii = TRUE)
#'   , identical(retrieve_object(conn = "iris_safer_2.txt", ascii = TRUE), iris)
#'   , unlink("iris_safer_2.txt") == 0
#' )
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' all(
#'   save_object(iris, alice$private_key, bob$public_key, conn = "iris_safer.bin")
#'   , identical(retrieve_object(conn = "iris_safer.bin", bob$private_key, alice$public_key), iris)
#'   , unlink("iris_safer.bin") == 0
#' )
#'
#' @export
#'
save_object     <- function(object
                            , key    = "pass"
                            , pkey   = NULL
                            , ascii  = FALSE
                            , conn){
  # assertions                           ----
  assert_that(!missing(object))
  assert_that(is.flag(ascii))
  assert_that(is.string(conn) || inherits(conn, "connection"))
  if(is.string(conn)){
    assert_that(!file.exists(conn))
    }
  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }

  # try to see if object is serializable ----
  serializedObject <- try(serialize(object, NULL), silent = TRUE)
  if(is.error(serializedObject)){
    stop("Unable to serialize 'object' using 'serialize' function")
  }

  if(is.string(key)){
    keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
    if(is.error(keyAsRaw)){
      stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
    }
  } else {
    keyAsRaw <- key
  }

  # encrypt raw data                     ----
  if(method == "symmetric"){
    object_enc_raw <- data_encrypt(serializedObject
                                   , keyAsRaw
                                   , hash(charToRaw("nounce"), size = 24))
  } else {
    object_enc_raw <- auth_encrypt(serializedObject
                                   , key
                                   , pkey
                                   , hash(charToRaw("nounce"), size = 24))
  }
  attributes(object_enc_raw) <- NULL

  # write to file                        ----
  if(ascii){
    # try to establish text file connection
    if(is.string(conn)){
      conn <- try(file(conn, "wt"), silent = TRUE)
      if(is.error(conn)){
        stop("Unable to create a writable text file at path: "
             , normalizePath(conn)
             )
      } else {
        on.exit(close(conn), add = TRUE)
      }
    }

    # try to write text file
    wr <- try(writeLines(base64encode(object_enc_raw), con = conn)
              , silent = TRUE
              )
    if(is.error(wr)){
      stop("Unable to write to the connection or file. Ensure that 'conn' is a open writable text connection")
    }
  } else { # binary case
    # try to establish raw file connection
    if(is.string(conn)){
      conn <- try(file(conn, "wb"), silent = TRUE)
      if(is.error(conn)){
        stop("Unable to create a writable raw connection at path: "
             , normalizePath(conn)
        )
      } else {
        on.exit(close(conn), add = TRUE)
        }
    }
    wr <- try(serialize(object_enc_raw, connection = conn), silent = TRUE)
    if(is.error(wr)){
      stop("Unable to write to the connection or file. Ensure that 'conn' is a open writable raw connection")
    }
  }
  return(invisible(TRUE))
}

#' @title Retrieve an object from a connection(or a file)
#' @description \code{save_object} encrypts a R object to raw or text connection
#'   or a file. \code{retrieve_object} decrypts a raw or a text connection or a
#'   file (encrypted by \code{save_object}). Note that \code{retrieve_object}
#'   returns the object.
#'
#' @param conn A connection or a file where the decrypted content is written. If
#'   \code{ascii} is TRUE, an decrypted text is written to the connection. Else,
#'   when \code{ascii} is FALSE(default), a raw object is written to the
#'   connection
#' @param key For symmetric decryption, 'pkey' should be NULL (default) and
#'   'key' can be either a string (Default is 'pass') or a raw object. For
#'   asymmetric decryption, both 'key' (private key of the decrypter) and 'pkey'
#'   (public key of the encrypter) should be raw objects.
#' @param pkey See 'key'
#' @param ascii TRUE, if the encrypted output is a string(written to the text
#'   connection). FALSE, if the encrypted output is a raw object(written to the
#'   raw connection)
#'
#' @return An invisible TRUE
#'
#' @examples
#' # symmetric case:
#' all(
#'   save_object(iris, conn = "iris_safer.bin")
#'   , identical(retrieve_object(conn = "iris_safer.bin"), iris)
#'   , unlink("iris_safer.bin") == 0
#' )
#'
#' all(
#'   save_object(iris, conn = "iris_safer_2.txt", ascii = TRUE)
#'   , identical(retrieve_object(conn = "iris_safer_2.txt", ascii = TRUE), iris)
#'   , unlink("iris_safer_2.txt") == 0
#' )
#'
#' # asymmetric case:
#' alice <- keypair()
#' bob   <- keypair()
#' all(
#'   save_object(iris, alice$private_key, bob$public_key, conn = "iris_safer.bin")
#'   , identical(retrieve_object(conn = "iris_safer.bin", bob$private_key, alice$public_key), iris)
#'   , unlink("iris_safer.bin") == 0
#' )
#'
#' @export
#'
retrieve_object <- function(conn
                            , key   = "pass"
                            , pkey  = NULL
                            , ascii = FALSE){
  # assertions                     ----
  if(!is.string(conn)){
    assert_that("connection" %in% class(conn))
  } else {
    assert_that(file.exists(conn))
  }
  if(is.null(pkey)){
    method <- "symmetric"
    assert_that(is.string(key) || is.raw(key))
  } else {
    method <- "asymmetric"
    assert_that(is.raw(key))
    assert_that(is.raw(pkey))
  }

  # try to read serialized content ----
  if(ascii){
    if(is.string(conn)){
      conn <- try(file(conn, "rt"), silent = TRUE)
      if(is.error(conn)){
        stop("Unable to read the text file. Ensure 'read' permission")
      } else {
        on.exit(close(conn), add = TRUE)
      }
    }

    encryptedText <- try(readLines(conn), silent = TRUE)

    if(is.error(encryptedText)){
      stop("Unable to read from connection or file. Ensure that the connection is open text connection")
      }

    encryptedObject <- try(base64decode(encryptedText), silent = TRUE)

    if(is.error(encryptedObject)){
      stop("Unable to decode the encrypted text. Ensure that connection or the file was written by 'save_object' function.")
    }
  } else { # binary case

    if(is.string(conn)){
      conn <- try(file(conn, "rb"), silent = TRUE)
      if(is.error(conn)){
        stop("Unable to read the file. Ensure 'read' permission")
      } else {
        on.exit(close(conn), add = TRUE)
      }
    }

    encryptedObject <- try(unserialize(conn), silent = TRUE)

    if(is.error(encryptedObject)){
      stop("Unable to 'unserialize' the connection or file. Ensure that the connection is open raw connection. Ensure that connection or the file was written by 'save_object' function.")
    }
  }

  if(is.string(key)){
    keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  } else {
    keyAsRaw <- key
  }

  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # decrypt                        ----
  if(method == "symmetric"){
    object_dec_raw <-
      try(data_decrypt(encryptedObject
                       , keyAsRaw
                       , hash(charToRaw("nounce"), size = 24))
          , silent = TRUE)
  } else {
    object_dec_raw <-
      try(auth_decrypt(encryptedObject
                       , key
                       , pkey
                       , hash(charToRaw("nounce"), size = 24))
          , silent = TRUE)
  }

  if(is.error(object_dec_raw)){
    stop("Unable to decrypt. Check whether the input was generated by 'save_object' function.")
  }

  # return                         ----
  return(unserialize(object_dec_raw))
}
