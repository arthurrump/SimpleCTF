module State

open StateStore
open System
open Markdig
open Markdig.Syntax
open Markdig.Renderers.Html
open Ganss.XSS

module Map =
    let update key defaultValue f map =
        let old = map |> Map.tryFind key |> Option.defaultValue defaultValue
        map |> Map.add key (f old)

type Username = Username of string with
    member this.Normalized with get() = match this with Username n -> Username (n.ToLowerInvariant())
    member this.Value = match this with Username n -> n
type UserRole =
    | Admin
    | Team
type User =
    { Username: Username
      Role: UserRole
      PasswordSalt: string
      PasswordHash: string }

type ChallengeId = ChallengeId of string with
    member this.Value = match this with ChallengeId id -> id
type Challenge =
    { Id: ChallengeId
      Title: string
      Description: string
      Score: int
      Link: string
      Flags: Set<string> }

type FlagSubmission =
    { ChallengeId: ChallengeId
      Flag: string
      Date: DateTimeOffset }

type State =
    { Users: Map<Username, User>
      Challenges: Map<ChallengeId, Challenge>
      ChallengeSolutions: Map<ChallengeId, int>
      Score: Map<Username, int>
      SolvedChallenges: Map<Username, Set<FlagSubmission>> }

let init () =
    { Users = Map.empty
      Challenges = Map.empty
      ChallengeSolutions = Map.empty
      Score = Map.empty
      SolvedChallenges = Map.empty }

type Event =
    | UserRegister of User
    | UserDelete of username: Username
    | ChallengeUpsert of challenge: Challenge
    | ChallengeDelete of ChallengeId
    | FlagSubmit of username: Username * submission: FlagSubmission

let private markdownToHtml =
    let sanitizer = HtmlSanitizer()
    fun markdown ->
        let doc = Markdown.Parse markdown
        for node in (doc :> Syntax.MarkdownObject).Descendants() do
            match node with
            | :? Inlines.LinkInline | :? Inlines.AutolinkInline ->
                node.GetAttributes().AddPropertyIfNotExist("target", "_blank")
                node.GetAttributes().AddPropertyIfNotExist("rel", "noreferrer noopener")
            | _ -> ()
        let html = doc.ToHtml()
        html |> sanitizer.Sanitize

let update msg state =
    match msg with
    | UserRegister user ->
        if state.Users |> Map.containsKey user.Username.Normalized then
            state, Error "The account already exists"
        else
            { state with Users = state.Users |> Map.add user.Username.Normalized user }, Ok ()
    | UserDelete username ->
        { state with Users = state.Users |> Map.remove username.Normalized }, Ok ()
    | ChallengeUpsert challenge ->
        let descriptionHtml = challenge.Description |> markdownToHtml
        let challenge = { challenge with Description = descriptionHtml }
        { state with Challenges = state.Challenges |> Map.add challenge.Id challenge }, Ok ()
    | ChallengeDelete challengeId ->
        { state with Challenges = state.Challenges |> Map.remove challengeId }, Ok ()
    | FlagSubmit (username, submission) ->
        match state.Challenges |> Map.tryFind submission.ChallengeId with
        | None ->
            state, Error "This is not a known challenge"
        | Some challenge ->
            if challenge.Flags |> Set.contains (submission.Flag.Trim()) then
                { state with
                    ChallengeSolutions = state.ChallengeSolutions |> Map.update submission.ChallengeId 0 ((+) 1)
                    Score = state.Score |> Map.update username 0 ((+) challenge.Score)
                    SolvedChallenges = state.SolvedChallenges |> Map.update username Set.empty (Set.add submission) }
                , Ok ()
            else
                { state with
                    Score = state.Score |> Map.update username 0 ((-) 1 >> max 0) }
                , Error "Incorrect flag"

let createStore path = new StateStore<State, Event, Result<unit, string>>(path, init, update)
