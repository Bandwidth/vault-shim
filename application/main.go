package application

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type Application struct {
	Executable string
	Dir        string
	Args       []string
	Env        []string

	//// Logger to use. Default is logrus.StandardLogger().
	Logger logrus.FieldLogger

	// Stdout to connect to spawned processes
	Stdout io.Writer

	// Stderr to connect to spawned processes
	Stderr io.Writer
}

// Creates a new Application.
func NewApplication() *Application {
	return &Application{
		Logger: logrus.StandardLogger(),
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// Run the application.
func (a *Application) Run() (*os.ProcessState, error) {
	// Take directory from application if specified
	dir := a.Dir
	if dir == "" {
		dir = "."
	}
	return a.run(dir)
}

// Run the application in the given directory
func (a *Application) run(dir string) (*os.ProcessState, error) {
	var err error
	fi, err := os.Stat(a.Executable)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory", a.Executable)
	}

	if fi.Mode()&0111 == 0 {
		return nil, fmt.Errorf("%s is not executable", a.Executable)
	}

	// Execute command in background
	cmd := exec.Command(a.Executable, a.Args...)
	cmd.Dir = dir
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr
	cmd.Env = a.Env
	// Place the process in its own process group. This ensures that
	// the executable will not be part of the foreground process group which would
	// be sent a SIGINT when Ctrl-c is pressed in an interactive shell.
	// Without this, the process would be sent a SIGINT immediately upon Ctrl-c
	// being pressed, likely terminating the process before we have a chance
	// to run any additional tasks.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("%s failed to start", a.Executable))
	}

	// Handle stop signals in background
	signaled := make(chan os.Signal, 1)
	signal.Notify(signaled, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Reset(syscall.SIGTERM, syscall.SIGINT)
	go func() {
		// Wait for a signal
		receivedSignal := <-signaled

		// Send SIGINT/SIGTERM to the process
		cmd.Process.Signal(receivedSignal)

		// Ignore future SIGINT/SIGTERM. Wait until the process exits or we get
		// SIGKILL'ed.
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
	}()

	if err = cmd.Wait(); err != nil {
		return cmd.ProcessState, errors.Wrap(err, fmt.Sprintf("%s exited with non-zero exit code", a.Executable))
	}

	return cmd.ProcessState, nil
}
