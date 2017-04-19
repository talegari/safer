#' @title Encrypt a connection or file
#'
#' @aliases encrypt_file
#' @description \code{encrypt_conn}(or \code{encrypt_file}) encrypts a raw
#'   connection to a text connection or a file. \code{decrypt_conn}(or
#'   \code{decrypt_file}) decrypts a text connection or a file (encrypted by
#'   \code{encrypt_conn} or \code{encrypt_file})
#'
#' @param plainConn A raw connection or a file to be encrypted
#' @param encryptedConn A text connection or a file where the encrypted string
#'   is to be written
#' @param key A string without embbeded NULL. Default is 'pass'.
#' @param method Currently, a stub. It should be 'symmetric'(default)
#'
#' @return An invisible TRUE
#'
#' @export
#'
encrypt_conn   <- function(plainConn
                           , encryptedConn
                           , key    = "pass"
                           , method = "symmetric"){
  # assertions            ----
  assert_that(inherits(plainConn, "connection") || is.string(plainConn))
  if(is.string(plainConn)){
    assert_that(file.exists(plainConn))
    plainConn <- try(file(plainConn, "rb"), silent = TRUE)
    if(is.error(plainConn)){
      stop("Unable to read (possibly permission problem) binary file: ", plainConn)
    } else {
      on.exit(close(plainConn), add = TRUE)
    }
  }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))
  assert_that(inherits(encryptedConn, "connection") || is.string(encryptedConn))
  if(is.string(encryptedConn)){
    assert_that(!file.exists(encryptedConn))
    encryptedConn <- try(file(encryptedConn, "wt"), silent = TRUE)
    if(is.error(encryptedConn)){
      stop("Unable to write(possibly permission problem) text file: "
           , encryptedConn)
    } else {
      on.exit(close(encryptedConn), add = TRUE)
    }
  }

  # encode file as string ----
  string <- try(base64encode(plainConn), silent = TRUE)
  if(is.error(string)){
    stop("Unable to read from the connection or file. Ensure that connection or file is a open readable binary connection.")
  }

  keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # encrypt               ----
  if(method == "symmetric"){
    string_enc_raw <- data_encrypt(charToRaw(string)
                                   , keyAsRaw
                                   , hash(charToRaw("nounce"), size = 24)
    )
  }

  # write                 ----
  wr <- try(writeLines(base64encode(string_enc_raw), encryptedConn)
            , silent = TRUE
            )
  if(is.error(wr)){
    stop("Unable to write to the connection or file. Ensure that 'encryptedConn' is a open writable text connection.")
  }
  return(invisible(TRUE))
}
encrypt_file   <- encrypt_conn

#' @title Decrypt a connection or file
#'
#' @aliases decrypt_file
#' @description \code{decrypt_conn}(or \code{decrypt_file}) decrypts a text
#'   connection or a file to a raw connection or a file. \code{decrypt_conn}(or
#'   \code{decrypt_file}) decrypts a text connection or a file (encrypted by
#'   \code{encrypt_conn} or \code{encrypt_file})
#'
#' @param encryptedConn A text connection or a file where the encrypted string
#'   was written
#' @param plainConn A raw connection or a file where decrypted content will be
#'   written to
#' @param key A string without embbeded NULL. Default is 'pass'.
#' @param method Currently, a stub. It should be 'symmetric'(default)
#'
#' @return An invisible TRUE
#'
#' @export
#'
decrypt_conn   <- function(encryptedConn
                           , plainConn
                           , key    = "pass"
                           , method = "symmetric"){

  # assertions ----
  assert_that(inherits(encryptedConn, "connection") || is.string(encryptedConn))
  if(is.string(encryptedConn)){

    assert_that(file.exists(encryptedConn))
    encryptedConn <- try(file(encryptedConn, "rt"), silent = TRUE)
    if(is.error(encryptedConn)){
      stop("Unable to read (possibly permission problem) text file: "
           , encryptedConn
           )
    } else {
      on.exit(close(encryptedConn), add = TRUE)
    }

  }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))
  assert_that(inherits(plainConn, "connection") || is.string(plainConn))
  if(is.string(plainConn)){

    assert_that(!file.exists(plainConn))
    plainConn <- file(plainConn, "wb")
    if(is.error(plainConn)){
      stop("Unable to write (possibly permission problem) binary file: "
           , plainConn
           )
    } else {
      on.exit(close(plainConn), add = TRUE)
    }

  }

  # read data  ----
  string <- try(readLines(encryptedConn), silent = TRUE)
  if(is.error(string)){
    stop("Unable to read from the connection or file. Ensure that connection or file is a open readable text connection.")
  }

  decoded_string <- try(base64decode(string), silent = TRUE)
  if(is.error(decoded_string)){
    stop("Unable to decode the text in the connection or file. Ensure that input was generated by 'encrypt_conn' or 'encrypt_file'")
  }

  keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # decrypt    ----
  if(method == "symmetric"){
    string_dec_raw <-
      try(data_decrypt(base64decode(string)
                       , keyAsRaw
                       , hash(charToRaw("nounce"), size = 24))
          , silent = TRUE)
  }

  if(is.error(string_dec_raw)){
    stop("Unable to decrypt. Check whether the input was generated by 'encrypt_conn' or 'encrypt_file' function. Check whether 'key' and 'method' are correct.")
  }

  # write      ----
  wr <- writeBin(base64decode(rawToChar(string_dec_raw)), con = plainConn)
  if(is.error(wr)){
    stop("Unable to write to connection or file. Ensure that the connection or the file is a open writable binary connection.")
  }
  return(invisible(TRUE))
}
decrypt_file   <- decrypt_conn