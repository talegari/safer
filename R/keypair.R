#' @title Generate a public key and private key pair
#' @description Using sodium's 'keygen' and 'pubkey' based on curve25519
#' @param seed A raw object. If NULL, a randon seed will be chosen.
#' @return A list with:
#' \itemize{
#' \item public_key: A raw object
#' \item private_key: A raw object
#' \item seed: A raw object
#' }
#' @examples
#' temp <- keypair()
#' str(temp)
#' @export
#'
keypair <- function(seed = NULL){
  if(!is.null(seed)){
    assertthat::assert_that(is.raw(seed))
  } else {
    seed <- sodium::random(32)
  }

  private_key <- sodium::keygen(seed = seed)
  list(public_key = sodium::pubkey(private_key)
       , private_key = private_key
       , seed = seed
       )
}
