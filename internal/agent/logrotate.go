package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RotatingWriter writes to a log file, rotating by size and keeping
// maxFiles old generations: app.log, app.log.1, app.log.2 ...
type RotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxSize  int64
	maxFiles int
	f        *os.File
	size     int64
}

func NewRotatingWriter(path string, maxSize int64, maxFiles int) (*RotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &RotatingWriter{path: path, maxSize: maxSize, maxFiles: maxFiles}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > w.maxSize {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingWriter) rotate() {
	w.f.Close()
	for i := w.maxFiles - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	os.Rename(w.path, w.path+".1")
	w.open()
}

func (w *RotatingWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.Close()
}

// tailLog returns the last n lines of the (possibly rotated) log for an assignment.
func tailLog(logDir, id string, n int) string {
	if n <= 0 {
		n = 100
	}
	base := filepath.Join(logDir, sanitize(id)+".log")
	var data []byte
	// oldest generation first so lines stay in order
	for i := 3; i >= 1; i-- {
		if b, err := os.ReadFile(fmt.Sprintf("%s.%d", base, i)); err == nil {
			data = append(data, b...)
		}
	}
	if b, err := os.ReadFile(base); err == nil {
		data = append(data, b...)
	}
	if len(data) == 0 {
		return "(暂无日志)\n"
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}
