module StateStore

open System
open System.IO
open System.Text.Json
open System.Text.Json.Serialization

type StateStore<'state, 'msg, 'res> (path: string, init: unit -> 'state, update: 'msg -> 'state -> 'state * 'res) =
    do if not (Directory.Exists path) then
        Directory.CreateDirectory path |> ignore

    let journalPath counter = Path.Combine(path, $"journal_%d{counter}")
    let openJournalReadStream counter =
        File.Open(journalPath counter, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read)
    let openJournalAppendStream counter =
        File.Open(journalPath counter, FileMode.Append, FileAccess.Write, FileShare.Read)

    let jsonOptions =
        let options = JsonSerializerOptions()
        options.Converters.Add(JsonFSharpConverter())
        options

    let mutable state = init ()
    let updateProcessor = new MailboxProcessor<'msg * AsyncReplyChannel<'state * 'res>>(fun proc ->
        let mutable journalCounter =
            let journalFileIds =
                Directory.EnumerateFiles(path)
                |> Seq.map (fun file -> Path.GetFileName(file).Split("_").[1] |> Int32.Parse)
            if journalFileIds |> Seq.isEmpty
            then 0
            else journalFileIds |> Seq.max
        let mutable currentJournal: FileStream = null

        let rec messageLoop () = async {
            let! holder = Async.OnCancel (fun () ->
                currentJournal.Flush ()
                currentJournal.Dispose ()
            )

            if currentJournal.Length > 25_000_000L then
                do! currentJournal.FlushAsync() |> Async.AwaitTask
                do! currentJournal.DisposeAsync().AsTask() |> Async.AwaitTask
                journalCounter <- journalCounter + 1
                currentJournal <- openJournalAppendStream journalCounter

            let! msg, reply = proc.Receive ()
            do! JsonSerializer.SerializeAsync(currentJournal, msg, jsonOptions) |> Async.AwaitTask
            currentJournal.WriteByte (byte '\n')
            do! currentJournal.FlushAsync () |> Async.AwaitTask
            let newState, response = update msg state
            state <- newState
            reply.Reply (state, response)

            holder.Dispose ()

            return! messageLoop ()
        }

        async {
            for i in 0..journalCounter do
                use stream = openJournalReadStream i
                use reader = new StreamReader (stream)
                while not reader.EndOfStream do
                    let! line = reader.ReadLineAsync() |> Async.AwaitTask
                    let msg = JsonSerializer.Deserialize<'msg>(line, jsonOptions)
                    state <- fst (update msg state)

            currentJournal <- openJournalAppendStream journalCounter

            return! messageLoop ()
        }
    )

    do updateProcessor.Start()

    member __.State = state
    member __.Dispatch (msg: 'msg) =
        let _, res = updateProcessor.PostAndReply (fun reply -> msg, reply)
        res
    member __.AsyncDispatch (msg: 'msg) =
        async {
            let! _, res = updateProcessor.PostAndAsyncReply (fun reply -> msg, reply)
            return res
        }
    member this.TaskDispatch (msg: 'msg) =
        this.AsyncDispatch(msg) |> Async.StartAsTask

    interface IDisposable with
        override __.Dispose () =
            (updateProcessor :> IDisposable).Dispose ()
