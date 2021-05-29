module Auth

open FSharp.Control.Tasks
open Falco.Security
open State
open System.Security.Claims
open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Http
open System
open System.Threading.Tasks

let private hash = Crypto.sha256 43000 32

module Result =
    let unwrapTask (res: Result<Task, 'b>) =
        task {
            match res with
            | Ok task ->
                do! task
                return Ok ()
            | Error err ->
                return Error err
        }

let registerUser role username password =
    let salt = Crypto.createSalt 16
    { Username = Username username
      Role = role
      PasswordSalt = salt
      PasswordHash = hash salt password }

let validateLogin username password state =
    let tryUser =
        state.Users
        |> Map.tryFind (Username username).Normalized
        |> Option.bind (fun user ->
            if hash user.PasswordSalt password = user.PasswordHash
            then Some user
            else None
        )
    match tryUser with
    | Some user -> Ok user
    | None -> Error "The user doesn't exist or the password is incorrect"

let userToClaimsPrincipal user =
    let claims = seq {
        Claim(ClaimTypes.Name, user.Username.Normalized.Value)
        Claim(ClaimTypes.Role, string user.Role)
    }
    let claimsIdentity = ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)
    ClaimsPrincipal(claimsIdentity)

let tryGetClaimsPrincipal username password =
    validateLogin username password >> Result.map userToClaimsPrincipal
