module SimpleCTF.Program

open Falco
open Falco.Routing
open Falco.HostBuilder
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Antiforgery
open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.Extensions.DependencyInjection

open State
open System
open Falco.Markup
open Falco.Security
open FSharp.Control.Tasks
open System.Security.Claims
open Microsoft.AspNetCore.Http

module Option =
    let toResult = function
        | Some value -> Ok value
        | None -> Error ()

type HttpContext with
    member ctx.TryGetUsername () =
        ctx.GetUser()
        |> Option.bind (fun cp ->
            if cp.HasClaim(fun claim -> claim.Type = ClaimTypes.Name)
            then Some (cp.FindFirstValue(ClaimTypes.Name))
            else None)
        |> Option.map (Username)

    member ctx.IsAuthenticatedInRole (role) =
        ctx.GetUser ()
        |> Option.map (fun cp -> cp.IsInRole role)
        |> Option.defaultValue false

let configureServices (services : IServiceCollection) =
    services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(fun options ->
            options.ExpireTimeSpan <- TimeSpan.FromMinutes(60.)
        ) |> ignore
    services
        .AddAntiforgery()
        .AddFalco()
        |> ignore

let configureApp (endpoints : HttpEndpoint list) (ctx : WebHostBuilderContext) (app : IApplicationBuilder) =
    let devMode = StringUtils.strEquals ctx.HostingEnvironment.EnvironmentName "Development"
    app.UseWhen(devMode, fun app ->
            app.UseDeveloperExceptionPage())
       .UseWhen(not(devMode), fun app ->
            app.UseFalcoExceptionHandler(Response.withStatusCode 500 >> Response.ofPlainText "Server error"))
       .UseAuthentication()
       .UseStaticFiles()
       .UseFalco(endpoints)
       |> ignore

let configureWebHost (endpoints : HttpEndpoint list) (webHost : IWebHostBuilder) =
    webHost
        .ConfigureServices(configureServices)
        .Configure(configureApp endpoints)

let master (ctx: HttpContext) title content =
    Elem.html [ Attr.lang "nl" ] [
        Elem.head [] [
            Elem.meta [ Attr.charset "utf-8" ]
            Elem.meta [ Attr.name "viewport"; Attr.content "width=device-width, initial-scale=1" ]
            Elem.title [] [ Text.rawf "%s - SimpleCTF" title ]
            Elem.link [ Attr.rel "stylesheet"; Attr.href "https://cdn.jsdelivr.net/npm/bulma@0.9.2/css/bulma.min.css" ]
            Elem.link [ Attr.rel "stylesheet"; Attr.href "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" ]
            Text.comment "👋 Je gaat hier geen flags vinden. Helaas."
        ]
        Elem.body [] [
            Elem.header [ ] [
                Elem.nav [ Attr.class' "navbar" ] [
                    Elem.div [ Attr.class' "container" ] [
                        Elem.div [ Attr.class' "navbar-brand" ] [ Elem.a [ Attr.class' "navbar-item"; Attr.href "/" ] [ Elem.h1 [] [ Text.raw "SimpleCTF" ] ] ]
                        Elem.div [ Attr.class' "navbar-start" ] [
                            if ctx.IsAuthenticated() then Elem.a [ Attr.class' "navbar-item"; Attr.href "/leaderboard" ] [ Text.raw "Leaderboard" ]
                            if ctx.IsAuthenticatedInRole (string Admin) then Elem.a [ Attr.class' "navbar-item"; Attr.href "/overview" ] [ Text.raw "Admin Overview" ]
                        ]
                        Elem.div [ Attr.class' "navbar-end" ] [
                            if ctx.IsAuthenticated() then
                                match ctx.TryGetUsername() with
                                | None -> ()
                                | Some username -> Elem.span [ Attr.class' "navbar-item" ] [ Text.enc username.Value ]
                                Elem.a [ Attr.class' "navbar-item"; Attr.href "/logout" ] [ Text.raw "Log uit" ]
                            else
                                Elem.a [ Attr.class' "navbar-item"; Attr.href "/login" ] [ Text.raw "Log in" ]
                                Elem.a [ Attr.class' "navbar-item"; Attr.href "/register"] [ Text.raw "Registreer" ]
                        ]
                    ]
                ]
            ]
            Elem.main [ Attr.class' "container section is-medium" ] content
            Elem.script [ Attr.src "/script.js" ] []
            // Elem.footer [ Attr.class' "footer" ] [
            //     Elem.div [ Attr.class' "content has-text-centered" ] [
            //         Elem.p [] [
            //             Elem.strong [] [ Text.raw "SimpleCTF" ]
            //             Text.raw " is gemaakt door "
            //             Elem.a [ Attr.href "https://arthurrump.com" ] [ Text.raw "Arthur Rump" ]
            //             Text.raw ". Bekijk de code op "
            //             Elem.a [ Attr.href "https://github.com/arthurrump/SimpleCTF" ] [ Text.raw "GitHub" ]
            //             Text.raw "."
            //         ]
            //     ]
            // ]
        ]
    ]

module Response =
    let ofHtmlMaster title content ctx =
        ctx |> Response.ofHtml (master ctx title (content ()))

    let ofHtmlMasterWithCsrf title content ctx =
        ctx |> Response.ofHtmlCsrf (fun token -> (master ctx title (content token)))

module Bulma =
    let field = Elem.div [ Attr.class' "field" ]
    let label = Elem.label [ Attr.class' "label" ]
    let control = Elem.div [ Attr.class' "control" ]
    let columns = Elem.div [ Attr.class' "columns" ]
    let messageBody style message = Elem.div [ Attr.class' $"message %s{style}" ] [ Elem.div [ Attr.class' "message-body" ] message ]

let loginForm (username, error) (token : AntiforgeryTokenSet) =
    Bulma.columns [
        Elem.form [ Attr.class' "box column is-half is-offset-one-quarter"; Attr.method "POST" ] [
            Bulma.field [ Elem.h1 [ Attr.class' "title" ] [ Text.raw "Log in" ] ]
            match error with
            | Ok _ -> ()
            | Error message -> Bulma.field [ Bulma.messageBody "is-danger" [ Text.raw message ] ]
            Bulma.field [
                Bulma.label [ Text.raw "Teamnaam / Gebruikersnaam" ]
                Bulma.control [
                    Elem.input [ Attr.name "username"; Attr.class' "input"; Attr.type' "text"; Attr.value username ]
                ]
            ]
            Bulma.field [
                Bulma.label [ Text.raw "Wachtwoord" ]
                Bulma.control [
                    Elem.input [ Attr.name "password"; Attr.class' "input"; Attr.type' "password" ]
                ]
            ]
            Xss.antiforgeryInput token
            Elem.div [ Attr.class' "field is-flex is-justify-content-space-between" ] [
                Bulma.control [
                    Elem.button [ Attr.class' "button is-link" ] [ Text.raw "Log in" ]
                ]
                Elem.p [ Attr.class' "control is-align-self-center" ] [
                    Text.raw "Nog geen account? "
                    Elem.a [ Attr.href "/register" ] [ Text.raw "Registreer" ]
                ]
            ]
        ]
    ]

let registerForm (username, password, error) (token : AntiforgeryTokenSet) =
    Bulma.columns [
        Elem.form [ Attr.class' "box column is-half is-offset-one-quarter"; Attr.method "POST" ] [
            Bulma.field [ Elem.h1 [ Attr.class' "title" ] [ Text.raw "Registreer" ] ]
            match error with
            | Ok _ -> ()
            | Error message -> Bulma.field [ Bulma.messageBody "is-danger" [ Text.raw message ] ]
            Bulma.field [
                Bulma.label [ Text.raw "Teamnaam" ]
                Bulma.control [
                    Elem.input [
                        Attr.name "username"
                        Attr.class' ("input" + match username with Ok _ -> "" | Error _ -> " is-danger")
                        Attr.type' "text"
                        Attr.value (match username with Ok un -> un | Error un -> un)
                    ]
                    match username with Ok _ -> () | Error _ -> Elem.p [ Attr.class' "help is-danger" ] [ Text.raw "Deze teamnaam is niet beschikbaar." ]
                ]
            ]
            Bulma.field [
                Bulma.label [ Text.raw "Wachtwoord" ]
                Bulma.control [
                    Elem.input [
                        Attr.name "password"
                        Attr.class' ("input" + match password with Ok _ -> "" | Error _ -> " is-danger")
                        Attr.type' "password"
                        Attr.value (match password with Ok pw -> pw | Error pw -> pw)
                    ]
                    match password with
                    | Ok _ -> Elem.p [ Attr.class' "help" ] [ Text.raw "Minimaal 12 tekens." ]
                    | Error _ -> Elem.p [ Attr.class' "help is-danger" ] [ Text.raw "Ongeldig wachtwoord. Gebruik een wachtwoord van minimaal 12 tekens." ]
                ]
            ]
            Xss.antiforgeryInput token
            Elem.div [ Attr.class' "field is-flex is-justify-content-space-between" ] [
                Bulma.control [
                    Elem.button [ Attr.class' "button is-link" ] [ Text.raw "Registreer" ]
                ]
                Elem.p [ Attr.class' "control is-align-self-center" ] [
                    Text.raw "Al een account? "
                    Elem.a [ Attr.href "/login" ] [ Text.raw "Log in" ]
                ]
            ]
        ]
    ]

let welcomeHome =
    Elem.div [] [
        Elem.div [ Attr.class' "block is-flex is-justify-content-center" ] [
            Elem.h1 [ Attr.class' "title" ] [ Text.raw "Welkom!" ]
        ]
        Elem.div [ Attr.class' "block buttons are-medium is-flex is-justify-content-center" ] [
            Elem.a [ Attr.class' "button is-link"; Attr.href "/login" ] [ Text.raw "Log in" ]
            Elem.a [ Attr.class' "button is-link"; Attr.href "/register" ] [ Text.raw "Registreer" ]
        ]
    ]

let challengeBox (challenge: Challenge) submitted (wrongSubmission: string option) (token: AntiforgeryTokenSet) =
    Elem.div [ Attr.id challenge.Id.Value; Attr.class' "box" ] [
        Elem.header [ Attr.class' "is-flex is-justify-content-space-between" ] [
            Elem.h2 [ Attr.class' "title is-4" ] [ Text.enc challenge.Title ]
            Elem.div [ Attr.class' "tags is-align-items-start" ] [
                Elem.span [ Attr.class' "tag is-medium is-primary" ] [ Text.rawf "%d pt" challenge.Score ]
            ]
        ]
        Elem.div [ Attr.class' "content" ] [
            Elem.h3 [ Attr.class' "title is-6 mb-0" ] [ Text.raw "Link" ]
            Elem.p [] [ Elem.a [ Attr.href challenge.Link; Attr.target "_blank"; Attr.rel "noreferrer noopener" ] [ Text.enc challenge.Link ] ]
            Elem.h3 [ Attr.class' "title is-6 mb-0" ] [ Text.raw "Beschrijving" ]
            Text.raw challenge.Description
        ]
        match submitted with
        | Some submission ->
            Elem.div [] [
                Elem.div [ Attr.class' "field has-addons" ] [
                    Elem.div [ Attr.class' "control has-icons-left" ] [
                        Elem.input [ Attr.class' "input is-success"; Attr.id $"%s{challenge.Id.Value}-solution-input"; Attr.type' "password"; Attr.readonly; Attr.value submission.Flag ]
                        Elem.span [ Attr.class' "icon is-small is-left has-text-success" ] [ Elem.i [ Attr.class' "fas fa-check" ] [] ]
                    ]
                    Bulma.control [
                        Elem.button [ Attr.class' "button is-success"; Attr.create "onclick" $"toggleSolutionVisibility('%s{challenge.Id.Value}')" ] [
                            Elem.span [ Attr.class' "icon" ] [
                                Elem.i [ Attr.id $"%s{challenge.Id.Value}-solution-button-eye"; Attr.class' "fas fa-eye" ] []
                                Elem.i [ Attr.id $"%s{challenge.Id.Value}-solution-button-eye-slash"; Attr.class' "fas fa-eye-slash"; Attr.style "display: none" ] []
                            ]
                        ]
                    ]
                ]
            ]
        | None ->
            Elem.form [ Attr.method "POST"; Attr.action $"/challenge/%s{challenge.Id.Value}" ] [
                Xss.antiforgeryInput (token: AntiforgeryTokenSet)
                Elem.div [ Attr.class' "field has-addons" ] [
                    Bulma.control [
                        Elem.input [ Attr.name "flag"; Attr.class' ("input" + if wrongSubmission.IsSome then " is-danger" else ""); Attr.type' "text"; Attr.placeholder "Flag"; Attr.value (wrongSubmission |> Option.defaultValue "") ]
                        if wrongSubmission.IsSome then Elem.p [ Attr.class' "help is-danger" ] [ Text.raw "Helaas, die flag is niet correct." ]
                    ]
                    Bulma.control [
                        Elem.button [ Attr.class' "button is-link" ] [ Text.raw "Verstuur" ]
                    ]
                ]
            ]
    ]

let challengeList challenges solved wrongSubmission token =
    Elem.div [] [
        Elem.h1 [ Attr.class' "title" ] [ Text.raw "Challenges" ]
        for challenge in challenges do
            let isSolved =
                let filtered = solved |> Set.filter (fun subm -> subm.ChallengeId = challenge.Id)
                if filtered |> Set.isEmpty
                then None
                else Some (filtered |> Set.minElement)
            let isWrong =
                wrongSubmission
                |> Option.bind (fun (challengeId, flag) -> if challengeId = challenge.Id then Some flag else None)
            challengeBox challenge isSolved isWrong token
    ]

let renderChallengeList state wrongSubmission (ctx: HttpContext) =
    let challenges = state.Challenges |> Map.toSeq |> Seq.map snd
    let solved =
        ctx.TryGetUsername()
        |> Option.bind (fun username ->
            state.SolvedChallenges
            |> Map.tryFind username)
        |> Option.defaultValue Set.empty
    fun token -> challengeList challenges solved wrongSubmission token

let home points =
    Elem.div [ Attr.class' "level" ] [
        Elem.div [ Attr.class' "level-item has-text-centered" ] [
            Elem.div [] [
                Elem.p [ Attr.class' "title is-1" ] [ Text.rawf "%d" points ]
                Elem.p [ Attr.class' "heading" ] [ Text.raw "Punten" ]
            ]
        ]
    ]

let renderHome state (ctx: HttpContext) =
    let points =
        ctx.TryGetUsername()
        |> Option.bind (fun username -> state.Score |> Map.tryFind username)
        |> Option.defaultValue 0
    home points

let leaderboard state (ctx: HttpContext) () =
    let scores =
        state.Score
        |> Map.toList
        |> List.groupBy snd
        |> List.sortByDescending fst
        |> List.indexed
        |> List.map (fun (index, (score, userScorePairs)) ->
            {| Index = index + 1; Score = score; Usernames = userScorePairs |> List.map fst |})
    let showScoreAllowed = ctx.IsAuthenticatedInRole (string Admin)
    let showScore =
        showScoreAllowed &&
        ctx.Request.GetQueryReader().TryGetString "showScore"
        |> Option.map (function "on" -> true | "off" -> false | _ -> false)
        |> Option.defaultValue false
    ctx.Response.SetHeader "Refresh" "60"
    [
        Elem.h1 [ Attr.class' "title" ] [ Text.raw "Leaderboard" ]
        Elem.div [ Attr.class' "box" ] [
            Elem.table [ Attr.class' "table is-hoverable" ] [
                Elem.thead [] [
                    Elem.tr [] [
                        Elem.th [] [ Text.raw "Positie" ]
                        Elem.th [] [ Text.raw "Team" ]
                        if showScore then Elem.th [] [ Text.raw "Punten" ]
                    ]
                ]
                Elem.tbody [] [
                    for score in scores do
                        for username in score.Usernames do
                            Elem.tr [] [
                                if username = score.Usernames.Head then Elem.td [ Attr.create "rowspan" (string score.Usernames.Length) ] [ Text.rawf "%d" score.Index ]
                                Elem.td [] [ Text.enc username.Value ]
                                if showScore then Elem.td [] [ Text.rawf "%d" score.Score ]
                            ]
                ]
            ]
        ]
        if showScoreAllowed then
            Elem.form [ Attr.method "GET"; Attr.class' "box" ] [
                Bulma.field [
                    Bulma.control [
                        Elem.label [ Attr.class' "checkbox" ] [
                            Elem.input [
                                Attr.name "showScore"
                                Attr.type' "checkbox"
                                if showScore then Attr.checked'
                                Attr.create "onchange" "this.form.submit()"
                            ]
                            Text.raw " Toon scores"
                        ]
                    ]
                ]
            ]
    ]

let adminOverview state () =
    let isSolvedBy (username: Username) challengeId =
        state.SolvedChallenges
        |> Map.tryFind (username.Normalized)
        |> Option.defaultValue Set.empty
        |> Set.exists (fun subm -> subm.ChallengeId = challengeId)

    [
        Elem.h1 [ Attr.class' "title" ] [ Text.raw "Admin overzicht" ]
        Elem.div [ Attr.class' "box" ] [
            Elem.div [ Attr.class' "table-container" ] [
                Elem.table [ Attr.class' "table is-hoverable" ] [
                    Elem.thead [] [
                        Elem.tr [] [
                            Elem.th [] []
                            Elem.th [] [ Text.raw "Score" ]
                            for challenge in state.Challenges do
                                Elem.th [] [ Text.enc challenge.Value.Title ]
                        ]
                    ]
                    Elem.tbody [] [
                        for KeyValue (_, team) in state.Users do
                            Elem.tr [] [
                                Elem.th [] [ Text.enc team.Username.Value ]
                                Elem.td [] [ Text.rawf "%d" (state.Score |> Map.tryFind (team.Username.Normalized) |> Option.defaultValue 0) ]
                                for challenge in state.Challenges do
                                    if challenge.Key |> isSolvedBy team.Username then
                                        Elem.td [ Attr.class' "has-text-success has-background-success-light" ] [ Elem.i [ Attr.class' "fas fa-check" ] [] ]
                                    else
                                        Elem.td [] []
                            ]
                    ]
                ]
            ]
        ]
    ]

[<EntryPoint>]
let main args =
    use state = State.createStore "./data"

    match args |> List.ofArray with
    | "admin"::args ->
        match args with
        | "register"::username::password::[] ->
            let user = Auth.registerUser Admin username password
            printfn "%A" (state.Dispatch (UserRegister user))
        | _ ->
            printfn "Usage:"
            printfn ""
    | _ ->
        webHost args {
            configure configureWebHost
            endpoints [
                get "/" (
                    Request.ifAuthenticated
                        (fun ctx -> ctx |> Response.ofHtmlMasterWithCsrf "Challenges" (fun token -> [
                            renderHome state.State ctx
                            renderChallengeList state.State None ctx token
                        ]))
                        (Response.ofHtmlMaster "Home" (fun () -> [ welcomeHome ]))
                )
                post "/challenge/{challengeId}" (
                    Request.ifAuthenticated
                        (Request.bindRoute
                            (fun routes -> routes.TryGet "challengeId" |> Option.bind (fun id -> state.State.Challenges |> Map.tryFind (ChallengeId id)) |> Option.toResult)
                            (fun challenge ->
                                Request.mapFormSecure
                                    (fun form -> form.Get "flag" "")
                                    (fun flag ->
                                        let flagSubmission = { ChallengeId = challenge.Id; Flag = flag; Date = DateTimeOffset.UtcNow }
                                        fun ctx -> task {
                                            match ctx.TryGetUsername () with
                                            | Some username ->
                                                match! state.TaskDispatch (FlagSubmit (username, flagSubmission)) with
                                                | Ok () ->
                                                    return! ctx |> Response.redirect $"/#%s{challenge.Id.Value}" false
                                                | Error _ ->
                                                    return! ctx
                                                        |> Response.withStatusCode 400
                                                        |> Response.ofHtmlMasterWithCsrf "Challenges" (renderChallengeList state.State (Some (challenge.Id, flag)) ctx >> List.singleton)
                                            | None ->
                                                return! ctx |> Response.withStatusCode 403 |> Response.ofPlainText "Not authenticated"
                                        }
                                    )
                                    (Response.withStatusCode 400 >> Response.ofEmpty)
                            )
                            (fun _ -> Response.withStatusCode 404 >> Response.ofPlainText "Not Found"))
                        (Response.withStatusCode 403 >> Response.ofPlainText "Not authenticated")
                )
                get "/leaderboard" (
                    Request.ifAuthenticated
                        (fun ctx -> ctx |> Response.ofHtmlMaster "Leaderboard" (leaderboard state.State ctx))
                        (Response.withStatusCode 403 >> Response.ofPlainText "Not authenticated")
                )
                get "/overview" (
                    Request.ifAuthenticatedInRole [ string Admin ]
                        (fun ctx -> ctx |> Response.ofHtmlMaster "Admin Overzicht" (adminOverview state.State))
                        (Response.withStatusCode 403 >> Response.ofPlainText "Not authenticated or not authorized")
                )
                all "/login" [
                    GET, Response.ofHtmlMasterWithCsrf "Login" (fun token -> [ loginForm ("", Ok ()) token ])
                    POST, Request.mapFormSecure
                            (fun form -> form.GetString "username" "", form.GetString "password" "")
                            (fun (username, password) ->
                                match Auth.tryGetClaimsPrincipal username password state.State with
                                | Ok cp ->
                                    Response.signInAndRedirect CookieAuthenticationDefaults.AuthenticationScheme cp "/"
                                | Error _ ->
                                    Response.withStatusCode 400
                                    >> Response.ofHtmlMasterWithCsrf "Login" (fun token -> [ loginForm (username, Error "Onjuiste teamnaam of wachtwoord.") token ]))
                            (Response.withStatusCode 400
                             >> Response.ofHtmlMasterWithCsrf "Login" (fun token ->  [ loginForm ("", Error "Invalide anti-CSRF token ontvangen. Probeer het opnieuw.") token ]))
                ]
                get "/logout" (Response.signOutAndRedirect CookieAuthenticationDefaults.AuthenticationScheme "/")
                all "/register" [
                    GET, Response.ofHtmlMasterWithCsrf "Registreer" (fun token -> [ registerForm (Ok "", Ok "", Ok ()) token ])
                    POST, Request.mapFormSecure
                            (fun form -> form.GetString "username" "", form.GetString "password" "")
                            (fun (username, password) ctx ->
                                task {
                                    if password.Length >= 12 then
                                        if username.Length <= 20 then
                                            let user = Auth.registerUser Team username password
                                            match! state.TaskDispatch (UserRegister user) with
                                            | Ok () ->
                                                let cp = Auth.userToClaimsPrincipal user
                                                return! ctx |> Response.signInAndRedirect CookieAuthenticationDefaults.AuthenticationScheme cp "/"
                                            | Error _ ->
                                                return! ctx
                                                    |> Response.withStatusCode 400
                                                    |> Response.ofHtmlMasterWithCsrf "Registreer" (fun token -> [ registerForm (Error username, Ok "", Ok ()) token ])
                                        else
                                            return! ctx
                                            |> Response.withStatusCode 400
                                            |> Response.ofHtmlMasterWithCsrf "Registreer" (fun token -> [ registerForm (Error username, Ok "", Error "De teamnaam mag niet langer zijn dan 20 tekens.") token ])
                                    else
                                        return! ctx
                                            |> Response.withStatusCode 400
                                            |> Response.ofHtmlMasterWithCsrf "Registreer" (fun token -> [ registerForm (Ok username, Error "", Ok ()) token ])
                                })
                            (Response.withStatusCode 400
                             >> Response.ofHtmlMasterWithCsrf "Registreer" (fun token -> [ registerForm (Ok "", Ok "", Error "Invalide anti-CSRF token ontvangen. Probeer het opnieuw.") token ]))
                ]
            ]
        }

    0
