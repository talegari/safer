#' @title safer
#'
#' @description A consistent interface to encrypt/decrypt strings, R objects,
#'   files. Alternatives for base R functions 'serialize/unserialize',
#'   'save/load' are provided.
#'
#'   The following functions are provided:
#'
#'   \strong{encrypt_string/decrypt_string}: \code{encrypt_string} encrypts a
#'   string as a string and \code{decrypt_string} decrypts the encrypted
#'   string(encrypted using \code{encrypt_string})
#'
#'   \strong{encrypt_object/decrypt object}: \code{encrypt_object} encrypts a R
#'   object as a raw object or a string and \code{decrypt_object} decrypts a raw
#'   object or a string(encrypted by \code{encrypt_object})
#'
#'   \strong{encrypt_file/decrypt_file}: \code{encrypt_file} encrypts file into
#'   another binary or ascii file. \code{decrypt_file}) decrypts a file
#'   (encrypted by \code{encrypt_file})
#'
#'   \strong{save_object/retrieve_object}: \code{save_object} encrypts a R
#'   object to raw or text connection or a file. \code{retrieve_object} decrypts
#'   a raw or a text connection or a file (encrypted by \code{save_object}.)
#'
#' @import sodium
#' @import base64enc
#' @import assertthat
#'
"_PACKAGE"
