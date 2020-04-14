package main

/*
 * note.go
 * Note template
 * By J. Stuart McMurray
 * Created 20200413
 * Last Modified 20200413
 */

// NoteTemplate is the template to use for ransom notes, as a format string
// passed to fmt.Fprint.  It will receive one argument, a string containing the
// generated ID as a base36-formatted uint64.
const NoteTemplate = `Oh, dear.

You seem to have been ransomwared.  This is unfortunate.  To recover your data
please pay a large amount of money to a bad guy.  You'll need to send the
following ID:

%s

We regret any inconvenience this may have caused.
`

var FilledNoteTemplate []byte
