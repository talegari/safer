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
keypair = function(seed = NULL){

  if(!is.null(seed)){
    assertthat::assert_that(is.raw(seed))
  } else {
    seed = sodium::random(32)
  }

  private_key = sodium::keygen(seed = seed)

  res = list(public_key = sodium::pubkey(private_key),
             private_key = private_key,
             seed = seed
             )

  return(res)
}

#' @title Read an existing public and private Ed25519 key pair
#' @description Reads Ed25519 keys from files using the openssl package. The public key is automatically derived from the private key file.
#' @param private_key_path Path to the private key file.
#' @return A list with:
#' \itemize{
#' \item public_key: A raw object
#' \item private_key: A raw object
#' \item seed: NULL
#' }
#' @examples
#' # Generate a keypair and save to disk using openssl
#' key = openssl::ed25519_keygen()
#' tmp = tempfile()
#' openssl::write_pem(key, tmp)
#'
#' # Read it back using read_keypair
#' keys = read_keypair(tmp)
#' str(keys)
#'
#' # Validate that keys are same
#' identical(keys$private_key, key$data)
#' identical(keys$public_key, key$pubkey$data)
#' @export
read_keypair = function(private_key_path) {

  if (!requireNamespace("openssl", quietly = TRUE)) {
    stop("Package 'openssl' is required to read existing key files.")
  }

  if (!file.exists(private_key_path)) {
    stop("Private key file not found at: ", private_key_path)
  }

  if (file.access(private_key_path, 4) != 0) {
    stop("No read permission for private key file at: ", private_key_path)
  }

  # Read private key
  key = tryCatch({
    openssl::read_key(private_key_path)
  }, error = function(e) {
    stop("Failed to read private key. Ensure it is a valid Ed25519 key file. Original error: ", e$message)
  })

  if (key$type != "ed25519") {
    stop("Only Ed25519 keys are supported. Detected key type: ", key$type)
  }

  private_key = key$data
  public_key = key$pubkey$data

  res = list(public_key = public_key,
             private_key = private_key,
             seed = NULL
             )
  return(res)
}
