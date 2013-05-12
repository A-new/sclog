VERSION 5.00
Begin VB.Form frmConvert 
   Caption         =   "Convert Hooks"
   ClientHeight    =   6720
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   12750
   LinkTopic       =   "Form1"
   ScaleHeight     =   6720
   ScaleWidth      =   12750
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton Command1 
      Caption         =   "Command1"
      Height          =   495
      Left            =   11100
      TabIndex        =   1
      Top             =   6240
      Width           =   1215
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   6135
      Left            =   60
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   0
      Text            =   "frmConvert.frx":0000
      Top             =   60
      Width           =   12495
   End
End
Attribute VB_Name = "frmConvert"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Private Sub Command1_Click()

    r = ""
    
    x = Split(Text1, vbCrLf)
    For Each y In x
        'ALLOC_THUNK( int      __stdcall Real_gethostname(char* a0,int a1));
        'FARPROC  (__stdcall *Real_GetProcAddress)(HMODULE a0,LPCSTR a1);
        If InStr(y, "ALLOC_") > 0 Then
            y = Replace(Trim(y), "ALLOC_THUNK(", Empty)
            y = Replace(Trim(y), ") );", "));")
            y = Replace(Trim(y), "));", ") = NULL;")
            y = Replace(Trim(y), "(", ")(")
            y = Replace(Trim(y), "__stdcall ", "(__stdcall *")
            
            r = r & y & vbCrLf
        End If
    Next
    
    Text1 = r
        
        
End Sub

