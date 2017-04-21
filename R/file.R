#' @title Encrypt a file
#'
#' @description \code{encrypt_file}) encrypts a file as a binary or a ascii
#'   file. \code{decrypt_file}) decrypts a text or a binary file (encrypted by
#'   \code{encrypt_file})
#'
#' @param infile file to be encrypted
#' @param outfile Non-existant file where the encrypted output is to be written
#' @param ascii \code{TRUE} if the outfile is to be encrypted as a ascii file.
#'   Default is \code{FALSE}
#' @param key A string without embbeded NULL. Default is 'pass'.
#' @param method Currently, a stub. It should be 'symmetric'(default)
#'
#' @return An invisible TRUE
#'
#' @examples
#' write.table(iris, "iris.csv")
#' all(
#'   encrypt_file("iris.csv", "iris_encrypted.bin")
#'   , file.exists("iris_encrypted.bin")
#'   , decrypt_file("iris_encrypted.bin", "iris_2.csv")
#'   , file.exists("iris_2.csv")
#'   , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
#'   , unlink("iris.csv") == 0
#'   , unlink("iris_2.csv") == 0
#'   , unlink("iris_encrypted.bin") == 0
#' )
#'
#' write.table(iris, "iris.csv")
#' all(
#'   encrypt_file("iris.csv", "iris_encrypted.txt", ascii = TRUE)
#'   , file.exists("iris_encrypted.txt")
#'   , decrypt_file("iris_encrypted.txt", "iris_2.csv", ascii = TRUE)
#'   , file.exists("iris_2.csv")
#'   , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
#'   , unlink("iris.csv") == 0
#'   , unlink("iris_2.csv") == 0
#'   , unlink("iris_encrypted.txt") == 0
#' )
#'
#' @export
#'
encrypt_file   <- function(infile
                           , outfile
                           , ascii  = FALSE
                           , key    = "pass"
                           , method = "symmetric"){
  # assertions            ----
  assert_that(is.string(infile))
  assert_that(file.exists(infile))
  infile <- try(file(infile, "rb"), silent = TRUE)
  if(is.error(infile)){
    stop("Unable to read (possibly permission problem) binary file: ", infile)
  } else {
    on.exit(close(infile), add = TRUE)
  }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))
  assert_that(is.string(outfile))
  assert_that(!file.exists(outfile))
  if(ascii){
    outfile <- try(file(outfile, "wt"), silent = TRUE)
  } else {
    outfile <- try(file(outfile, "wb"), silent = TRUE)
  }

  if(is.error(outfile)){
    stop("Unable to write(possibly permission problem) file: "
         , outfile)
  } else {
    on.exit(close(outfile), add = TRUE)
  }

  # encode file as string ----
  string <- try(base64encode(infile), silent = TRUE)
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
  attributes(string_enc_raw) <- NULL

  # write                 ----
  if(ascii){
    wr <- try(writeLines(base64encode(string_enc_raw), outfile)
              , silent = TRUE
              )
  } else {
    wr <- try(serialize(string_enc_raw, outfile), silent = TRUE)
  }

  if(is.error(wr)){
    stop("Unable to write to the file.")
  }
  return(invisible(TRUE))
}

#' @title Decrypt a connection or file
#'
#' @aliases decrypt_file
#' @description \code{decrypt_file}) decrypts a binary or a text file back to a
#'   file.
#'
#' @param infile Encrypted file.
#' @param outfile A non-existant file where the decrypted output will be
#'   written.
#' @param ascii \code{TRUE} if the outfile is a ascii file. Default is
#'   \code{FALSE}
#' @param key A string without embbeded NULL. Default is 'pass'.
#' @param method Currently, a stub. It should be 'symmetric'(default).
#'
#' @return An invisible TRUE
#'
#' @examples
#' write.table(iris, "iris.csv")
#' all(
#'   encrypt_file("iris.csv", "iris_encrypted.bin")
#'   , file.exists("iris_encrypted.bin")
#'   , decrypt_file("iris_encrypted.bin", "iris_2.csv")
#'   , file.exists("iris_2.csv")
#'   , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
#'   , unlink("iris.csv") == 0
#'   , unlink("iris_2.csv") == 0
#'   , unlink("iris_encrypted.bin") == 0
#' )
#'
#' write.table(iris, "iris.csv")
#' all(
#'   encrypt_file("iris.csv", "iris_encrypted.txt", ascii = TRUE)
#'   , file.exists("iris_encrypted.txt")
#'   , decrypt_file("iris_encrypted.txt", "iris_2.csv", ascii = TRUE)
#'   , file.exists("iris_2.csv")
#'   , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
#'   , unlink("iris.csv") == 0
#'   , unlink("iris_2.csv") == 0
#'   , unlink("iris_encrypted.txt") == 0
#' )
#'
#' @export
#'
decrypt_file   <- function(infile
                           , outfile
                           , ascii  = FALSE
                           , key    = "pass"
                           , method = "symmetric"){

  # assertions ----
  assert_that(is.string(infile))
  assert_that(file.exists(infile))
  if(ascii){
    infile <- try(file(infile, "rt"), silent = TRUE)
  } else {
    infile <- try(file(infile, "rb"), silent = TRUE)
  }

  if(is.error(infile)){
    stop("Unable to read (possibly permission problem) file: "
         , infile
         )
  } else {
    on.exit(close(infile), add = TRUE)
  }
  assert_that(is.string(key))
  assert_that(method %in% c("symmetric"))

  assert_that(is.string(outfile))
  assert_that(!file.exists(outfile))
  outfile <- try(file(outfile, "wb"), silent = TRUE)
  if(is.error(outfile)){
    stop("Unable to write (possibly permission problem) file: "
         , outfile
         )
  } else {
    on.exit(close(outfile), add = TRUE)
  }


  # read data  ----
  if(ascii){
    string <- try(readLines(infile), silent = TRUE)
    if(is.error(string)){
      stop("Unable to read from the file.")
    }
  } else {
    decoded_string <- try(unserialize(infile)
                          , silent = TRUE) # actually not a string
    if(is.error(decoded_string)){
      stop("Unable to decode the file. Ensure that input was generated by encrypt_file'.")
    }
  }

  if(ascii){
    decoded_string <- try(base64decode(string), silent = TRUE)
    if(is.error(decoded_string)){
      stop("Unable to decode the text in the file. Ensure that input was generated by encrypt_file'")
    }
  }

  keyAsRaw <- try(hash(charToRaw(key)), silent = TRUE)
  if(is.error(keyAsRaw)){
    stop("Unable to convert 'key' into raw. Possibly encountered an embedded NULL.")
  }

  # decrypt    ----
  if(method == "symmetric"){
    string_dec_raw <-
      try(data_decrypt(decoded_string
                       , keyAsRaw
                       , hash(charToRaw("nounce"), size = 24))
          , silent = TRUE)
  }

  if(is.error(string_dec_raw)){
    stop("Unable to decrypt. Check whether the input was generated by 'encrypt_file' function. Check whether 'key' and 'method' are correct.")
  }

  # write      ----
  wr <- writeBin(base64decode(rawToChar(string_dec_raw)), con = outfile)
  if(is.error(wr)){
    stop("Unable to write to connection or file.")
  }
  return(invisible(TRUE))
}
