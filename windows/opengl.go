// OpenGL without cgo on Windows
// $ CGO_ENABLED=0 go build -ldflags -H=windowsgui opengl.go
//
// Note: uintptr casts of Go pointers must be done in the call site in
// order to avoid collection of the object before the call.
//
// This is free and unencumbered software released into the public domain.

package main

import (
	"math"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	CreateWindowExA  = user32.NewProc("CreateWindowExA")
	DefWindowProcA   = user32.NewProc("DefWindowProcA")
	DispatchMessageA = user32.NewProc("DispatchMessageA")
	GetDC            = user32.NewProc("GetDC")
	LoadCursorA      = user32.NewProc("LoadCursorA")
	PeekMessageA     = user32.NewProc("PeekMessageA")
	PostQuitMessage  = user32.NewProc("PostQuitMessage")
	RegisterClassA   = user32.NewProc("RegisterClassA")
	ShowWindow       = user32.NewProc("ShowWindow")
	TranslateMessage = user32.NewProc("TranslateMessage")

	gdi32             = syscall.NewLazyDLL("gdi32.dll")
	ChoosePixelFormat = gdi32.NewProc("ChoosePixelFormat")
	SetPixelFormat    = gdi32.NewProc("SetPixelFormat")
	SwapBuffers       = gdi32.NewProc("SwapBuffers")

	opengl32            = syscall.NewLazyDLL("opengl32.dll")
	glClear             = opengl32.NewProc("glClear")
	glDrawArrays        = opengl32.NewProc("glDrawArrays")
	glEnable            = opengl32.NewProc("glEnable")
	glFrustum           = opengl32.NewProc("glFrustum")
	glGetError          = opengl32.NewProc("glGetError")
	glInterleavedArrays = opengl32.NewProc("glInterleavedArrays")
	glLightfv           = opengl32.NewProc("glLightfv")
	glLoadIdentity      = opengl32.NewProc("glLoadIdentity")
	glMaterialf         = opengl32.NewProc("glMaterialf")
	glMatrixMode        = opengl32.NewProc("glMatrixMode")
	glRotatef           = opengl32.NewProc("glRotatef")
	glScalef            = opengl32.NewProc("glScalef")
	glShadeModel        = opengl32.NewProc("glShadeModel")
	glTranslatef        = opengl32.NewProc("glTranslatef")
	wglCreateContext    = opengl32.NewProc("wglCreateContext")
	wglGetProcAddress   = opengl32.NewProc("wglGetProcAddress")
	wglMakeCurrent      = opengl32.NewProc("wglMakeCurrent")

	glu32          = syscall.NewLazyDLL("glu32.dll")
	gluPerspective = glu32.NewProc("gluPerspective")
)

const (
	WS_OVERLAPPED  = 0x00000000
	WS_MINIMIZEBOX = 0x00020000
	WS_SYSMENU     = 0x00080000

	WM_CLOSE = 0x0010
	WM_QUIT  = 0x0012

	GL_PROJECTION = 0x1701
	GL_MODELVIEW  = 0x1700

	GL_DEPTH_TEST = 0xb71
	GL_CULL_FACE  = 0xb44
	GL_LIGHTING   = 0xb50
	GL_NORMALIZE  = 0xba1

	GL_FRONT_AND_BACK = 0x0408

	GL_FLAT = 0x1d00

	GL_LIGHT0 = 0x4000

	GL_AMBIENT   = 0x00001200
	GL_DIFFUSE   = 0x00001201
	GL_POSITION  = 0x00001203
	GL_SHININESS = 0x00001601

	GL_DEPTH_BUFFER_BIT = 0x0100
	GL_COLOR_BUFFER_BIT = 0x4000

	GL_QUADS = 0x0007

	GL_V3F     = 0x2a21
	GL_C3F_V3F = 0x2a24
	GL_N3F_V3F = 0x2a25
)

func proc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CLOSE:
		PostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := DefWindowProcA.Call(hwnd, msg, wparam, lparam)
	return r
}

func main() {
	var (
		classname = unsafe.Pointer(&[]byte("gl\x00")[0])
		title     = unsafe.Pointer(&[]byte("OpenGL Cube\x00")[0])
		wndclass  struct {
			style      uint32
			wndproc    uintptr
			clsextra   int32
			wndextra   int32
			hinstance  uintptr
			icon       uintptr
			cursor     uintptr
			background uintptr
			menuname   uintptr
			classname  uintptr
		}
	)

	wndclass.wndproc = syscall.NewCallback(proc)
	wndclass.classname = uintptr(classname)
	wndclass.cursor, _, _ = LoadCursorA.Call(0, 0x7f00)
	RegisterClassA.Call(uintptr(unsafe.Pointer(&wndclass)))

	hwnd, _, _ := CreateWindowExA.Call(
		0, uintptr(classname), uintptr(title),
		WS_OVERLAPPED|WS_MINIMIZEBOX|WS_SYSMENU,
		450, 50, 800, 800, 0, 0, 0, 0,
	)
	hdc, _, _ := GetDC.Call(hwnd)

	pfd := make([]uint32, 10)
	pfd[1] = 37
	ppfd := unsafe.Pointer(&pfd[0])
	idx, _, _ := ChoosePixelFormat.Call(hdc, uintptr(ppfd))
	SetPixelFormat.Call(hdc, idx, uintptr(ppfd))
	ctx, _, _ := wglCreateContext.Call(hdc)
	wglMakeCurrent.Call(hdc, ctx)
	ShowWindow.Call(hwnd, 1)

	cube := []float32{
		+0, +0, +1, -1, -1, +1,
		+0, +0, +1, +1, -1, +1,
		+0, +0, +1, +1, +1, +1,
		+0, +0, +1, -1, +1, +1,

		+0, +0, -1, -1, -1, -1,
		+0, +0, -1, +1, -1, -1,
		+0, +0, -1, +1, +1, -1,
		+0, +0, -1, -1, +1, -1,

		+0, +1, +0, -1, +1, -1,
		+0, +1, +0, +1, +1, -1,
		+0, +1, +0, +1, +1, +1,
		+0, +1, +0, -1, +1, +1,

		+0, -1, +0, -1, -1, -1,
		+0, -1, +0, +1, -1, -1,
		+0, -1, +0, +1, -1, +1,
		+0, -1, +0, -1, -1, +1,

		+1, +0, +0, +1, -1, -1,
		+1, +0, +0, +1, +1, -1,
		+1, +0, +0, +1, +1, +1,
		+1, +0, +0, +1, -1, +1,

		-1, +0, +0, -1, -1, -1,
		-1, +0, +0, -1, +1, -1,
		-1, +0, +0, -1, +1, +1,
		-1, +0, +0, -1, -1, +1,
	}
	pcube := unsafe.Pointer(&cube[0])

	glEnable.Call(GL_DEPTH_TEST)
	glEnable.Call(GL_NORMALIZE)
	glEnable.Call(GL_LIGHTING)
	glShadeModel.Call(GL_FLAT)

	glEnable.Call(GL_LIGHT0)
	glLightfv.Call(
		GL_LIGHT0, GL_AMBIENT, uintptr(unsafe.Pointer(&[]float32{
			1, 0, 1, 1,
		}[0])),
	)
	glLightfv.Call(
		GL_LIGHT0, GL_DIFFUSE, uintptr(unsafe.Pointer(&[]float32{
			1, 0, 1, 1,
		}[0])),
	)
	glLightfv.Call(
		GL_LIGHT0, GL_POSITION, uintptr(unsafe.Pointer(&[]float32{
			4, 1, 4, 1,
		}[0])),
	)
	glMaterialf.Call(
		GL_FRONT_AND_BACK,
		GL_SHININESS,
		uintptr(math.Float32bits(0.1)),
	)

	glMatrixMode.Call(GL_PROJECTION)
	gluPerspective.Call(
		uintptr(math.Float64bits(60.0)),
		uintptr(math.Float64bits(1.0)),
		uintptr(math.Float64bits(1.0)),
		uintptr(math.Float64bits(20.0)),
	)
	glMatrixMode.Call(GL_MODELVIEW)

	start := time.Now()
	for {
		var msg struct {
			hwnd           uintptr
			message        uint32
			wparam, lparam uintptr
			time           uint32
			x, y           int32
			priv           uint32
		}
		pmsg := unsafe.Pointer(&msg)
		for {
			r, _, _ := PeekMessageA.Call(uintptr(pmsg), 0, 0, 0, 1)
			if r == 0 {
				break
			}
			if msg.message == WM_QUIT {
				return
			}
			TranslateMessage.Call(uintptr(pmsg))
			DispatchMessageA.Call(uintptr(pmsg))
		}

		glClear.Call(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)

		glLoadIdentity.Call()
		glTranslatef.Call(
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(-2.0)),
		)

		now := time.Now().Sub(start).Seconds()
		xrot := float32(now * math.Sqrt(101))
		yrot := float32(now * math.Sqrt(137))
		zrot := float32(now * math.Sqrt(179))
		glRotatef.Call(
			uintptr(math.Float32bits(xrot)),
			uintptr(math.Float32bits(1.0)),
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(0.0)),
		)
		glRotatef.Call(
			uintptr(math.Float32bits(yrot)),
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(1.0)),
			uintptr(math.Float32bits(0.0)),
		)
		glRotatef.Call(
			uintptr(math.Float32bits(zrot)),
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(0.0)),
			uintptr(math.Float32bits(1.0)),
		)
		glScalef.Call(
			uintptr(math.Float32bits(0.5)),
			uintptr(math.Float32bits(0.5)),
			uintptr(math.Float32bits(0.5)),
		)

		glInterleavedArrays.Call(GL_N3F_V3F, 0, uintptr(pcube))
		glDrawArrays.Call(GL_QUADS, 0, uintptr(len(cube)/6))
		SwapBuffers.Call(hdc)
	}
}
