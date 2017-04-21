#' @title Save a R object to a connection
#'
#' @aliases save2
#' @description \code{save_object} encrypts a R object to raw or text connection
#'   or a file. \code{retrieve_object} decrypts a raw or a text connection or a
#'   file (encrypted by \code{save_object}). Note that \code{retrieve_object}
#'   returns the object.
#'
#' @param object A R object to be encrypted
#' @param conn A connection or a file where the encrypted content is written. If
#'   \code{ascii} is TRUE, an encrypted text is written to the connection. Else,
#'   when \code{ascii} is FALSE(default), a raw object is written to the
#'   connection
#' @param ascii TRUE, if the encrypted output is a string(written to the text
#'   connection). FALSE, if the encrypted output is a raw object(written to the
#'   raw connection)
#' @param key A string without embbeded NULL. Default is 'pass'
#' @param method Currently, a stub. It should be 'symmetric'(default)
#'
#' @return An invisible TRUE
#'
#' @examples
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
#' @export
#'
save_object     <- function(object
                            , conn
                            , ascii  = FALSE
                            , key    = "pass"
                            , method = "symmetric"){
  # assertions                           ----
  assert_that(!missing(object))
  assert_that(is.flag(ascii))
  assert_that(is.string(conn) || inherits(conn, "connection"))
  if(is.string(conn)){
    assert_that(!file.exists(conn))
    }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))

  # try to see if object is serializable ----
  serializedObject <- try(serialize(object, NULL), silent = TRUE)
  if(is.error(serializedObject)){
    stop("Unable to serialize 'object' using 'serialize' function")
  }

  keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # encrypt raw data                     ----
  if(method == "symmetric"){
    object_enc_raw <- data_encrypt(serializedObject
                                   , keyAsRaw
                                   , hash(charToRaw("nounce"), size = 24)
    )
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
  return(TRUE)
}

#' @title Retrieve a R object from a connection
#'
#' @aliases load2
#' @description \code{save_object} encrypts a R object to raw or text connection
#'   or a file. \code{retrieve_object} decrypts a raw or a text connection or a
#'   file (encrypted by \code{save_object}). Note that \code{retrieve_object}
#'   returns the object.
#'
#' @param conn A connection or a file to be decrypted.
#' @param ascii TRUE, if conn is a text connection or a ascii file. FALSE, if
#'   conn is a raw connection or a binary file
#' @param key A string without embbeded NULL. Default is 'pass'.
#' @param method Currently, a stub. It should be 'symmetric'(default).
#'
#' @return An invisible TRUE
#'
#' @examples
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
#' @export
#'
retrieve_object <- function(conn
                            , ascii  = FALSE
                            , key    = "pass"
                            , method = "symmetric"){
  # assertions                     ----
  if(!is.string(conn)){
    assert_that("connection" %in% class(conn))
  } else {
    assert_that(file.exists(conn))
  }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))

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
      stop("Unable to decode the encrypted text. Ensure that connection or the file was written by 'save_object' or 'save2' function")
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
      stop("Unable to 'unserialize' the connection or file. Ensure that the connection is open raw connection. Ensure that connection or the file was written by 'save_object' or 'save2' function")
    }
  }

  keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # decrypt                        ----
  if(method == "symmetric"){
    object_dec_raw <-
      try(data_decrypt(encryptedObject
                       , hash(charToRaw(key))
                       , hash(charToRaw("nounce"), size = 24))
          , silent = TRUE)
  }

  if(is.error(object_dec_raw)){
    stop("Unable to decrypt. Check whether the input was generated by 'save_object' or 'save2' function. Check whether 'key' and 'method' are correct.")
  }

  # return                         ----
  return(unserialize(object_dec_raw))
}
