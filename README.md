safer
=============

> A consistent interface to encrypt/decrypt strings, objects, files and
> connections in R. Both symmetric and asymmetric encryption methods are
> supported. Thanks to excellent packages `sodium` and `base64enc`.

### Design

There are four functions and their *(inverses)*.

-   `encryt_string` (`decrypt_string`)
-   `encryt_object` (`decrypt_object`)
-   `encryt_file` (`decrypt_file`)
-   `save_object` (`retrieve_object`)

The following table summarizes their functionality:

<table>
<thead>
<tr class="header">
<th>
Function
</th>
<th>
Input
</th>
<th>
Output
</th>
<th>
Has side-effect
</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>
encryt\_string
</td>
<td>
a string
</td>
<td>
string/raw
</td>
<td>
No
</td>
</tr>
<tr class="even">
<td>
encryt\_object
</td>
<td>
a R object
</td>
<td>
raw/string
</td>
<td>
No
</td>
</tr>
<tr class="odd">
<td>
encrypt\_file
</td>
<td>
a file on disk
</td>
<td>
<code>TRUE</code>
</td>
<td>
Yes (Output to disk)
</td>
</tr>
<tr class="even">
<td>
save\_object
</td>
<td>
a R object
</td>
<td>
<code>TRUE</code>
</td>
<td>
Yes (Output to disk)
</td>
</tr>
</tbody>
</table>
### Examples

    library("safer")

#### String

    # symmetric case:
    temp <- encrypt_string("hello, how are you", key = "secret")
    all(
      is.character(temp)
      , decrypt_string(temp, "secret") == "hello, how are you"
      , class(try(decrypt_string(temp, "nopass"), silent = TRUE)) == "try-error"
      )

    ## [1] TRUE
    
    res <- encrypt_string("tatvamasi", ascii = FALSE)
    isTRUE(identical(decrypt_string(res), "tatvamasi"))
    
    ## [1] TRUE
    
    # asymmetric case:
    alice <- keypair()
    bob   <- keypair()
    temp  <- encrypt_string("hello asymmetric", alice$private_key, bob$public_key)
    temp2 <- decrypt_string(temp, bob$private_key, alice$public_key)
    identical("hello asymmetric", temp2)

    ## [1] TRUE

Henceforth, we shall default password for symmetric case: `pass`.

#### Object

    # symmetric case:
    temp <- encrypt_object(1:3)
    all(
      is.raw(temp)
      , decrypt_object(temp) == 1:3)

    ## [1] TRUE

    temp <- encrypt_object(iris, ascii = TRUE)
    all(
      is.character(temp)
      , decrypt_object(temp) == iris
      , identical(decrypt_object(temp), iris))

    ## [1] TRUE

    rm(temp)

    # asymmetric case:
    alice <- keypair()
    bob   <- keypair()
    temp  <- encrypt_object(1:10, alice$private_key, bob$public_key)
    temp2 <- decrypt_object(temp, bob$private_key, alice$public_key)
    identical(1:10, temp2)

    ## [1] TRUE

#### File

    # symmetric case:
    write.table(iris, "iris.csv")
    all(
      encrypt_file("iris.csv", outfile = "iris_encrypted.bin")
      , file.exists("iris_encrypted.bin")
      , decrypt_file("iris_encrypted.bin", outfile = "iris_2.csv")
      , file.exists("iris_2.csv")
      , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
      , unlink("iris.csv") == 0
      , unlink("iris_2.csv") == 0
      , unlink("iris_encrypted.bin") == 0
    )

    ## [1] TRUE

    write.table(iris, "iris.csv")
    all(
      encrypt_file("iris.csv", outfile = "iris_encrypted.txt", ascii = TRUE)
      , file.exists("iris_encrypted.txt")
      , decrypt_file("iris_encrypted.txt", outfile = "iris_2.csv", ascii = TRUE)
      , file.exists("iris_2.csv")
      , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
      , unlink("iris.csv") == 0
      , unlink("iris_2.csv") == 0
      , unlink("iris_encrypted.txt") == 0
    )

    ## [1] TRUE

    # asymmetric case:
    alice <- keypair()
    bob   <- keypair()
    write.table(iris, "iris.csv")
    all(
      encrypt_file("iris.csv", alice$private_key, bob$public_key, outfile = "iris_encrypted.bin")
      , file.exists("iris_encrypted.bin")
      , decrypt_file("iris_encrypted.bin", bob$private_key, alice$public_key, outfile = "iris_2.csv")
      , file.exists("iris_2.csv")
      , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
      , unlink("iris.csv") == 0
      , unlink("iris_2.csv") == 0
      , unlink("iris_encrypted.bin") == 0
    )

    ## [1] TRUE

#### Save

    # symmetric case:
    all(
      save_object(iris, conn = "iris_safer.bin")
      , identical(retrieve_object(conn = "iris_safer.bin"), iris)
      , unlink("iris_safer.bin") == 0
    )

    ## [1] TRUE

    all(
      save_object(iris, conn = "iris_safer_2.txt", ascii = TRUE)
      , identical(retrieve_object(conn = "iris_safer_2.txt", ascii = TRUE), iris)
      , unlink("iris_safer_2.txt") == 0
    )

    ## [1] TRUE

    # asymmetric case:
    alice <- keypair()
    bob   <- keypair()
    all(
      save_object(iris, alice$private_key, bob$public_key, conn = "iris_safer.bin")
      , identical(retrieve_object(conn = "iris_safer.bin", bob$private_key, alice$public_key), iris)
      , unlink("iris_safer.bin") == 0
    )

    ## [1] TRUE
