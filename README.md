------------------------------------------------------------------------

Introduction
------------

The package intends to provide a consistent interface to encrypt/decrypt
strings, R objects, files. This is based on the excellent packages
`sodium` and `base64enc`. Currently, only symmetric key encryption (same
key to encrypt and decrypt) is used.

Design
------

There are four functions and their *(inverses)*.

-   `encryt_string` (`decrypt_string`)
-   `encryt_object` (`decrypt_object`)
-   `encryt_file` (`decrypt_file`)
-   `save_object` (`retrieve_object`)

The following table summarizes their functionality:

<table>
<thead>
<tr class="header">
<th>Function</th>
<th>Input</th>
<th>Output</th>
<th>Has side-effect</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>encryt_string</td>
<td>a string</td>
<td>string</td>
<td>No</td>
</tr>
<tr class="even">
<td>encryt_object</td>
<td>a R object</td>
<td>raw/string</td>
<td>No</td>
</tr>
<tr class="odd">
<td>encrypt_file</td>
<td>a file on disk</td>
<td><code>TRUE</code></td>
<td>Yes (Output to disk)</td>
</tr>
<tr class="even">
<td>save_object</td>
<td>a R object</td>
<td><code>TRUE</code></td>
<td>Yes (Output to disk)</td>
</tr>
</tbody>
</table>

Examples
--------

    library("safer")

### String

    temp <- encrypt_string("hello, how are you", key = "secret")
    all(
      is.character(temp)
      , decrypt_string(temp, "secret") == "hello, how are you"
      , class(try(decrypt_string(temp, "nopass"), silent = TRUE)) == "try-error")

    ## [1] TRUE

Henceforth, we shall default password: `pass`.

### Object

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

### File

     write.table(iris, "iris.csv")
     all(
       encrypt_file("iris.csv", "iris_encrypted.bin")
       , file.exists("iris_encrypted.bin")
       , decrypt_file("iris_encrypted.bin", "iris_2.csv")
       , file.exists("iris_2.csv")
       , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
       , unlink("iris.csv") == 0
       , unlink("iris_2.csv") == 0
       , unlink("iris_encrypted.bin") == 0
     )

    ## [1] TRUE

     write.table(iris, "iris.csv")
     all(
       encrypt_file("iris.csv", "iris_encrypted.txt", ascii = TRUE)
       , file.exists("iris_encrypted.txt")
       , decrypt_file("iris_encrypted.txt", "iris_2.csv", ascii = TRUE)
       , file.exists("iris_2.csv")
       , tools::md5sum("iris_2.csv") == tools::md5sum("iris.csv")
       , unlink("iris.csv") == 0
       , unlink("iris_2.csv") == 0
       , unlink("iris_encrypted.txt") == 0
     )

    ## [1] TRUE

### Save

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

