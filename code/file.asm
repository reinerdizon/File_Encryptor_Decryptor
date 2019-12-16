; ***************************************************************
;	Reiner Dizon
;	File Encyptor/Decyptor Program
;	CS 218-1002
;
; This program obtains command line arguments when
; running the executable file. Depending on the encrypt/decrypt
; specifier, the program will encrypt the given input file and
; writes to the given output file. Reading the input file
; involves the use of a buffer of size BUFF_SIZE. Output from
; the program is written to the given output file or displayed
; on the terminal only if an error is encountered.

; ***************************************************************
;  Data declarations
;	Note, the error message strings should NOT be changed.
;	All other variables may changed or ignored...

section	.data

; -----
;  Define standard constants.

TRUE		equ	1
FALSE		equ	0

SUCCESS		equ	0			; successful operation
NOSUCCESS	equ	1			; unsuccessful operation

STDIN		equ	0			; standard input
STDOUT		equ	1			; standard output
STDERR		equ	2			; standard error

SYS_read	equ	0			; system call code for read
SYS_write	equ	1			; system call code for write
SYS_open	equ	2			; system call code for file open
SYS_close	equ	3			; system call code for file close
SYS_lseek	equ	8			; system call code for file repositioning
SYS_fork	equ	57			; system call code for fork
SYS_exit	equ	60			; system call code for terminate
SYS_creat	equ	85			; system call code for file open/create
SYS_time	equ	201			; system call code for get time

LF		equ	10
SPACE		equ	" "
NULL		equ	0
ESC		equ	27

O_CREAT		equ	0x40
O_TRUNC		equ	0x200
O_APPEND	equ	0x400

O_RDONLY	equ	000000q			; file permission - read only
O_WRONLY	equ	000001q			; file permission - write only
O_RDWR		equ	000002q			; file permission - read and write

S_IRUSR		equ	00400q
S_IWUSR		equ	00200q
S_IXUSR		equ	00100q

; -----
;  Define program specific constants.

KEY_MAX		equ	56
KEY_MIN		equ	16

BUFF_SIZE	equ	800000			; buffer size

; -----
;  Variables for getOptions() function.

eof		db	FALSE

usageMsg	db	"Usage: blowfish <-en|-de> -if <inputFile> "
		db	"-of <outputFile>", LF, NULL
errIncomplete	db	"Error, command line arguments incomplete."
		db	LF, NULL
errExtra	db	"Error, too many command line arguments."
		db	LF, NULL
errFlag		db	"Error, encryption/decryption flag not "
		db	"valid.", LF, NULL
errReadSpec	db	"Error, invalid read file specifier.", LF, NULL
errWriteSpec	db	"Error, invalid write file specifier.", LF, NULL
errReadFile	db	"Error, opening input file.", LF, NULL
errWriteFile	db	"Error, opening output file.", LF, NULL

; -----
;  Variables for getX() function.

buffMax		dq	BUFF_SIZE-1
curr		dq	BUFF_SIZE
wasEOF		db	FALSE

errRead		db	"Error, reading from file.", LF,
		db	"Program terminated.", LF, NULL

; -----
;  Variables for writeX() function.

errWrite	db	"Error, writting to file.", LF,
		db	"Program terminated.", LF, NULL

; -----
;  Variables for readKey() function.

chr		db	0

keyPrompt	db	"Enter Key (16-56 characters): ", NULL
keyError	db	"Error, invalid key size.  Key must be between 16 and "
		db	"56 characters long.", LF, NULL

; ------------------------------------------------------------------------
;  Unitialized data

section	.bss

buffer		resb	BUFF_SIZE


; ############################################################################

section	.text

; ***************************************************************
;  Routine to get arguments (encryption flag, input file
;	name, and output file name) from the command line.
;	Verify files by atemptting to open the files (to make
;	sure they are valid and available).

;  Command Line format:
;	./blowfish <-en|-de> -if <inputFileName> -of <outputFileName>

; -----
;  Arguments:
;	argc (value)
;	address of argv table
;	address of encryption/decryption flag (byte)
;	address of read file descriptor (qword)
;	address of write file descriptor (qword)
;  Returns:
;	TRUE or FALSE
global getOptions
getOptions:
	push	rbx	; store preserved registers
	push	r12
	push	r13
	push	r14
	push	r15
	
	; store arguments onto preserved registers
	mov	r12, rsi	; ARGV
	mov	r13, rdx	; enc/dec flag
	mov	r14, rcx	; read file descriptor
	mov	r15, r8		; write file descriptor
	
usageErrChk: ; usage error check
	; if(argc != 1), go to argcErrChk
	cmp	rdi, 1
	jne	argcErrChk
	; otherwise
	mov	rdi, usageMsg
	call	printString	; prt usage msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
argcErrChk: ; check for incomplete argument
	; if(argc >= 6), go to argcErrChk2
	cmp	rdi, 6
	jge	argcErrChk2
	; otherwise
	mov	rdi, errIncomplete
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
argcErrChk2: ; check for extra argument
	; if(argc == 6), go to flagErrChk
	cmp	rdi, 6
	je	flagErrChk
	; otherwise
	mov	rdi, errExtra
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
flagErrChk: ; checking flag specifier
	mov	rbx, qword [r12 + 8]	; get argv[1] addr
	
	; if(argv[1] == "-en"), go to enFlag
	cmp	dword [rbx], 0x0071732d
	je	enFlag
	; if(argv[1] == "-de"), go to deFlag
	cmp	dword [rbx], 0x0065642d
	je	deFlag
	
	; otherwise
	mov	rdi, errFlag
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
enFlag: ; setting encryptFlag to TRUE
	mov	byte [r13], TRUE
	jmp	ifSpecErrChk
	
deFlag: ; setting encryptFlag to FALSE
	mov	byte [r13], FALSE
	jmp	ifSpecErrChk
	
ifSpecErrChk: ; checking "-if" specifier
	mov	rbx, qword [r12 + 16]	; get argv[2] addr
	
	; if(argv[2] == "-if"), go to inputFileErrChk
	cmp	dword [rbx], 0x0066692d
	je	inputFileErrChk
	; otherwise
	mov	rdi, errReadSpec
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
inputFileErrChk: ; checking if valid input file (handled by OS)
	mov	rbx, qword [r12 + 24]	; get argv[3] addr
	
	mov	rax, SYS_open		; system call for file open
	mov	rdi, rbx		; ebx = file name string
	mov	rsi, O_RDONLY		; read only access
	syscall				; call the kernel

	cmp	rax, 0			; check for success
	jge	ofSpecErrChk
	
	; cannot open
	mov	rdi, errReadFile
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
ofSpecErrChk: ; checking "-of" specifier
	mov	qword [r14], rax	; if opened, save descriptor
	mov	rbx, qword [r12 + 32]	; get argv[4] addr
	
	; if(argv[4] == "-of"), go to outputFileErrChk
	cmp	dword [rbx], 0x00666f2d
	je	outputFileErrChk
	; otherwise
	mov	rdi, errWriteSpec
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
outputFileErrChk: ; checking if valid output file (handled by OS)
	mov	rbx, qword [r12 + 40]	; get argv[5] addr
	
	mov	rax, SYS_creat		; sys call for file open/create
	mov	rdi, rbx		; ebx = file name string
	mov	rsi, S_IRUSR | S_IWUSR	; allow read/write access 
	syscall				; call the kernel

	cmp	rax, 0			; check for success
	jge	errChkDone
	
	; cannot open
	mov	rdi, errWriteFile
	call	printString	; prt error msg
	mov	al, FALSE	; return false
	jmp	getOptionsFinish
	
errChkDone: ; no errors, return TRUE
	mov	qword [r15], rax	; if opened, save descriptor
	mov	al, TRUE		; return true
	
getOptionsFinish:
	pop	r15	; restore preserved registers
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret




; ***************************************************************
;  Return the X array, 8 characters, from read buffer.
;	This routine performs all buffer management.

; -----
;   Arguments:
;	value of read file descriptor
;	address of X array
;  Returns:
;	TRUE or FALSE

;     NOTE's:
;	- returns TRUE when X array has been filled
;	- if < 8 characters in buffer, NULL fill
;	- returns FALSE only when asked for 8 characters
;		but there are NO more at all (which occurs
;		only when ALL previous characters have already
;		been returned).

;  The read buffer itself and some misc. variables are used
;  ONLY by this routine and as such are not passed.

global getX
getX:
	push	rbx	; store preserved registers
	push	r12
	push	r13
	push	r14
	push	r15
	
	; store arguments onto preserved registers
	mov	r12, rdi	; value of read file descriptor
	mov	r13, rsi	; addr of X array
		
	mov	r14, 0			; i = 0
	mov	qword [r13], NULL	; set xArr = all NULLs
	
getNxtChr:
	; if(curr > buffMax){ (A)
	mov	rax, qword [curr] 
	cmp	rax, qword [buffMax]
	jbe	initCmpFinish
	
	; if(wasEOF and i < 8 and xArr != NULL)
	cmp	byte [wasEOF], TRUE
	jne	wasEOFfinalChk
	cmp	r14, 8
	jge	wasEOFfinalChk
	cmp	qword [r13], NULL
	je	wasEOFfinalChk
	mov	al, TRUE		; return TRUE
	jmp	getXFinish		; exit
	
wasEOFfinalChk:	
	; if(wasEOF) (occurs once)
	cmp	byte [wasEOF], TRUE
	je	exitWithFalse		; exit with FALSE
	
	mov	rax, 0			; j = 0
bufferClearLp:
	; if (j >= BUFF_SIZE) go to readFile
	cmp	rax, BUFF_SIZE
	jge	readFile
	; otherwise
	mov	byte [buffer+rax], NULL	; buffer[j] = NULL
	inc	rax			; j++
	jmp	bufferClearLp
	
readFile:
	; read file
	mov	rax, SYS_read
	mov	rdi, r12
	mov	rsi, buffer
	mov	rdx, BUFF_SIZE
	syscall
	
	; if (status < 0), go to errorOnRead
	cmp	rax, 0
	jl	errorOnRead
	
	; if(actualRd == 0)
	cmp	rax, 0
	je	exitWithFalse	; exit with FALSE
	
	; if(actualRd < requestedRd){
	cmp	rax, BUFF_SIZE
	jae	LessThanRequestedRdDone
	
	mov	byte [wasEOF], TRUE	; wasEOF = TRUE
	mov	qword [buffMax], rax	; buffMax = actualRd
	;	}
	; }
	
LessThanRequestedRdDone:
	mov	qword [curr], 0		; curr = 0
	; } // end if (A)
	
initCmpFinish:
	mov	rbx, qword [curr]	; rbx = curr
	mov	al, byte [buffer+rbx]	; al = buffer [curr]
	mov	byte [r13 + r14], al	; xArr[i] = al
	inc	r14			; i++
	inc	qword [curr]		; curr++
	
	; if (i < 8), go to getNxtChr
	cmp	r14, 8
	jl	getNxtChr
	; otherwise
	mov	al, TRUE	; return TRUE
	jmp	getXFinish	; exit
	
errorOnRead:
	mov	rdi, errRead
	call	printString	; print error msg
	jmp	exitWithFalse	; exit with FALSE
	
exitWithFalse:
	mov	al, FALSE	; return FALSE
	jmp	getXFinish	; exit
	
getXFinish:
	pop	r15	; restore preserved registers
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret




; ***************************************************************
;  Write X array (8 characters) to output file.
;	No requirement to buffer here.

;     NOTE:	for encryption write -> always write 8 characters
;		for decryption write -> exclude any trailing NULLS

;     NOTE:	this routine returns FALSE only if there is an
;		error on write (which would not normally occur).

; -----
;  Arguments are:
;	value of write file descriptor
;	address of X array
;	value of encryption flag
;  Returns:
;	TRUE or FALSE
global writeX
writeX:
	push	rbx		; store preserved registers
	push	r12
	push	r13
	push	r14
		
	; store arguments onto the stack & preserved registers
	mov	r12, rdi	; value of write file descriptor
	mov	r13, rsi	; addr of X array
	mov	r14, rdx	; value of encryption flag
	
	; if(encryptFlag){	// encrypt write
	cmp	r14, TRUE
	jne	decryptWriteStart
	
	;  Call OS to write string
	mov	rax, SYS_write		; system code for write()
	mov	rdi, r12		; file descriptor
	mov	rsi, r13		; addr of char to write
	mov	rdx, 8			; rdx = count to write
	syscall
	
	; if(rax < 0), go to errorOnWrite
	cmp	rax, 0
	jl	errorOnWrite
	mov	al, TRUE	; otherwise, return TRUE
	jmp	writeXDone
	; }
	
decryptWriteStart:
	; else{	// decryptWrite
	mov	rdx, 0		; i = 0
	
decryptWriteCountLp: ; counting characters
	; if (xArr[i] == NULL), go to decryptWriteCountLpDone
	cmp	byte [r13+rdx], NULL
	je	decryptWriteCountLpDone
	inc	rdx		; otherwise, i++
	jmp	decryptWriteCountLp
	
decryptWriteCountLpDone:
	; if (i = 0), go to writeXDone
	cmp	rdx, 0
	je	writeXDone
	; otherwise, call OS to write string
	mov	rax, SYS_write		; system code for write()
	mov	rsi, r13		; addr of char to write
	mov	rdi, r12		; file descriptor
					; rdx = char count
	syscall
	
	; if(rax < 0), go to errorOnWrite
	cmp	rax, 0
	jl	errorOnWrite
	mov	al, TRUE	; otherwise, return TRUE
	jmp	writeXDone
	; }
	
errorOnWrite:
	mov	rdi, errWrite
	call	printString	; print error msg
	mov	al, FALSE	; return false
	jmp	writeXDone
	
writeXDone:
	pop	r14	; restore preserved registers
	pop	r13
	pop	r12
	pop	rbx
	ret




; ***************************************************************
;  Get a encryption/decryption key from user.
;	Key must be between MIN and MAX characters long.

;     NOTE:	must ensure there are no buffer overflow
;		if the user enters >MAX characters

; -----
;  Arguments:
;	address of the key buffer
;	value of key MIN length
;	value of key MAX length
global readKey
readKey:
	push	rbx		; store preserved registers
	push	r12
	push	r13
	push	r14
	push	r15
	
	; store arguments onto preserved registers
	mov	r12, rdi	; addr of key buffer
	mov	r13, rsi	; value of KEY_MIN
	mov	r14, rdx	; value of KEY_MAX
	
promptToScr:
	mov	rdi, keyPrompt
	call	printString		; print prompt
	lea	rbx, byte [r12]		; pointer to keyBuff
	mov	r15, 0			; count = 0
	
nxtChr:
	; read one char at a time
	mov	rax, SYS_read
	mov	rdi, STDIN
	mov	rsi, chr		; rsi = chr
	mov	rdx, 1
	syscall				
	
	mov	al, byte [chr]	; al = character
	; if (LF is pressed), go to inputDone
	cmp	al, LF
	je	inputDone
	inc	r15		; otherwise, count++
	
	; if (count > MAX_LENGTH), go back to nxtChr 
	cmp	r15, r14
	jg	nxtChr
	; otherwise write char to allocated char array
	mov	byte [rbx], al
	inc	rbx		; addr++
	jmp	nxtChr
	
inputDone:
	mov	byte [rbx], NULL	; add NULL to end string
	; if !(min <= count <= max), go to readKeyInputErr
	cmp	r15, r13
	jb	readKeyInputErr
	cmp	r15, r14
	ja	readKeyInputErr
	jmp	readKeyFinish	; otherwise, go to readKeyFinish
	
readKeyInputErr:
	mov	rdi, keyError
	call	printString	; prt error msg
	jmp	promptToScr
	
readKeyFinish:
	pop	r15		; restore preserved registers
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret



; ***************************************************************
;  Generic function to display a string to the screen.
;  String must be NULL terminated.

;  Algorithm:
;	Count characters in string (excluding NULL)
;	Use syscall to output characters

; -----
;  HLL Call:
;	printString(stringAddr);

;  Arguments:
;	1) address, string
;  Returns:
;	nothing

global	printString
printString:

; -----
;  Count characters to write.

	mov	rdx, 0
strCountLoop:
	cmp	byte [rdi+rdx], NULL
	je	strCountLoopDone
	inc	rdx
	jmp	strCountLoop
strCountLoopDone:
	cmp	rdx, 0
	je	printStringDone

; -----
;  Call OS to output string.

	mov	rax, SYS_write			; system code for write()
	mov	rsi, rdi			; address of char to write
	mov	rdi, STDOUT			; file descriptor for std in
						; rdx=count to write, set above
	syscall					; system call

; -----
;  String printed, return to calling routine.

printStringDone:
	ret

; ***************************************************************

