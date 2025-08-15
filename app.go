package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var startTime = time.Now()

// AppModel represents the terminal application state
type AppModel struct {
	currentDemo int
	demos       []string
	animFrame   int
	ticker      *time.Ticker
	config      *Config
	isAdmin     bool
	width       int
	height      int
}

// NewAppModel creates a new application model
func NewAppModel(config *Config, isAdmin bool) AppModel {
	return AppModel{
		currentDemo: 0,
		demos: []string{
			"Colors & Attributes",
			"Box Drawing",
			"Animation",
			"Progress Bars",
			"Matrix Rain",
			"Sine Wave",
			"Admin Panel",
		},
		animFrame: 0,
		ticker:    nil,
		config:    config,
		isAdmin:   isAdmin,
		width:     80,
		height:    24,
	}
}

// tickMsg is sent for animation updates
type tickMsg time.Time

// Init initializes the application
func (m AppModel) Init() tea.Cmd {
	return tick()
}

// tick returns a command that sends a tick message every 50ms
func tick() tea.Cmd {
	return tea.Tick(time.Millisecond*50, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles user input and updates the model
func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.animFrame++
		return m, tick()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "left", "h":
			m.currentDemo--
			if m.currentDemo < 0 {
				m.currentDemo = len(m.demos) - 1
			}
			m.animFrame = 0
		case "right", "l":
			m.currentDemo++
			if m.currentDemo >= len(m.demos) {
				m.currentDemo = 0
			}
			m.animFrame = 0
		case "r":
			m.animFrame = 0
		}
	}
	return m, nil
}

// View renders the current state of the application
func (m AppModel) View() string {
	var content string

	// Header
	header := fmt.Sprintf("\033[1;36m╔%s╗\033[0m\n", strings.Repeat("═", m.width-2))
	title := " VT100/ANSI Terminal Sequences Demo "
	padding := (m.width - len(title)) / 2
	header += fmt.Sprintf("\033[1;36m║\033[0m%s\033[1;33m%s\033[0m%s\033[1;36m║\033[0m\n",
		strings.Repeat(" ", padding), title, strings.Repeat(" ", m.width-padding-len(title)-2))
	header += fmt.Sprintf("\033[1;36m╚%s╝\033[0m\n", strings.Repeat("═", m.width-2))

	// Demo selector
	selector := "\033[90m"
	for i, demo := range m.demos {
		if i == m.currentDemo {
			selector += fmt.Sprintf(" \033[1;32m[%s]\033[0m", demo)
		} else {
			selector += fmt.Sprintf("\033[90m %s \033[0m", demo)
		}
	}
	selector += "\033[0m\n\n"

	// Render current demo
	switch m.currentDemo {
	case 0:
		content = m.renderColorsDemo()
	case 1:
		content = m.renderBoxDrawingDemo()
	case 2:
		content = m.renderAnimationDemo()
	case 3:
		content = m.renderProgressBarsDemo()
	case 4:
		content = m.renderMatrixRainDemo()
	case 5:
		content = m.renderSineWaveDemo()
	case 6:
		if m.isAdmin {
			content = m.renderAdminPanel()
		} else {
			content = "\033[31mAccess Denied: Admin privileges required\033[0m\n"
		}
	}

	// Footer with controls
	footer := fmt.Sprintf("\n\033[90m%s\033[0m\n", strings.Repeat("─", m.width))
	footer += "\033[36m← →\033[0m Navigate  \033[36mr\033[0m Reset  \033[36mq\033[0m Quit  "
	footer += fmt.Sprintf("\033[90mFrame: %d  Size: %dx%d\033[0m", m.animFrame, m.width, m.height)

	return header + selector + content + footer
}

func (m AppModel) renderColorsDemo() string {
	var s strings.Builder

	// Basic colors
	s.WriteString("\033[1mBasic Colors:\033[0m\n")
	colors := []struct {
		name string
		code string
	}{
		{"Black", "30"}, {"Red", "31"}, {"Green", "32"}, {"Yellow", "33"},
		{"Blue", "34"}, {"Magenta", "35"}, {"Cyan", "36"}, {"White", "37"},
	}
	for _, c := range colors {
		s.WriteString(fmt.Sprintf("\033[%sm■ %s\033[0m  ", c.code, c.name))
	}
	s.WriteString("\n\n")

	// Bright colors
	s.WriteString("\033[1mBright Colors:\033[0m\n")
	for _, c := range colors {
		s.WriteString(fmt.Sprintf("\033[1;%sm■ Bright %s\033[0m  ", c.code, c.name))
		if c.name == "Yellow" {
			s.WriteString("\n")
		}
	}
	s.WriteString("\n\n")

	// Background colors
	s.WriteString("\033[1mBackground Colors:\033[0m\n")
	for i := 40; i <= 47; i++ {
		s.WriteString(fmt.Sprintf("\033[%dm  \033[0m", i))
	}
	s.WriteString("\n\n")

	// Text attributes
	s.WriteString("\033[1mText Attributes:\033[0m\n")
	s.WriteString("\033[1mBold\033[0m  ")
	s.WriteString("\033[2mDim\033[0m  ")
	s.WriteString("\033[3mItalic\033[0m  ")
	s.WriteString("\033[4mUnderline\033[0m  ")
	s.WriteString("\033[5mBlink\033[0m  ")
	s.WriteString("\033[7mReverse\033[0m  ")
	s.WriteString("\033[9mStrikethrough\033[0m\n\n")

	// 256 color palette sample
	s.WriteString("\033[1m256 Color Palette Sample:\033[0m\n")
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			color := i*16 + j
			s.WriteString(fmt.Sprintf("\033[48;5;%dm  \033[0m", color))
		}
		s.WriteString("\n")
	}

	return s.String()
}

func (m AppModel) renderBoxDrawingDemo() string {
	var s strings.Builder

	s.WriteString("\033[1mBox Drawing Characters:\033[0m\n\n")

	// Single line box
	s.WriteString("Single Line:\n")
	s.WriteString("┌────────────────┐\n")
	s.WriteString("│ Hello, World!  │\n")
	s.WriteString("├────────────────┤\n")
	s.WriteString("│ Box drawing    │\n")
	s.WriteString("└────────────────┘\n\n")

	// Double line box
	s.WriteString("Double Line:\n")
	s.WriteString("╔════════════════╗\n")
	s.WriteString("║ Double Border  ║\n")
	s.WriteString("╠════════════════╣\n")
	s.WriteString("║ Fancy!         ║\n")
	s.WriteString("╚════════════════╝\n\n")

	// Mixed box with tree structure
	s.WriteString("Tree Structure:\n")
	s.WriteString("Root\n")
	s.WriteString("├── Branch 1\n")
	s.WriteString("│   ├── Leaf 1.1\n")
	s.WriteString("│   └── Leaf 1.2\n")
	s.WriteString("├── Branch 2\n")
	s.WriteString("│   ├── Leaf 2.1\n")
	s.WriteString("│   ├── Leaf 2.2\n")
	s.WriteString("│   └── Leaf 2.3\n")
	s.WriteString("└── Branch 3\n")
	s.WriteString("    └── Leaf 3.1\n")

	return s.String()
}

func (m AppModel) renderAnimationDemo() string {
	var s strings.Builder

	s.WriteString("\033[1mAnimations:\033[0m\n\n")

	// Spinner
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinner := spinners[m.animFrame%len(spinners)]
	s.WriteString(fmt.Sprintf("Loading... \033[32m%s\033[0m\n\n", spinner))

	// Moving block
	position := m.animFrame % 40
	s.WriteString("Moving Block:\n")
	s.WriteString(strings.Repeat(" ", position))
	s.WriteString("\033[41m  \033[0m\n\n")

	// Color cycle
	colors := []string{"31", "33", "32", "36", "34", "35"}
	color := colors[(m.animFrame/5)%len(colors)]
	s.WriteString(fmt.Sprintf("\033[%smColor Cycling Text\033[0m\n\n", color))

	// Pulsing text using dim/bright
	if m.animFrame%20 < 10 {
		s.WriteString("\033[1mPulsing Bright\033[0m\n")
	} else {
		s.WriteString("\033[2mPulsing Dim\033[0m\n")
	}
	s.WriteString("\n")

	// ASCII art animation
	frames := []string{
		"    o\n   /|\\\n   / \\",
		"    o\n   \\|/\n   / \\",
		"    o\n   /|\\\n   / \\",
		"    o\n   \\|/\n   / \\",
	}
	s.WriteString("Dancing Figure:\n")
	s.WriteString(frames[(m.animFrame/10)%len(frames)])

	return s.String()
}

func (m AppModel) renderProgressBarsDemo() string {
	var s strings.Builder

	s.WriteString("\033[1mProgress Bars:\033[0m\n\n")

	// Simple progress bar
	progress := (m.animFrame * 2) % 101
	filled := progress * 30 / 100
	s.WriteString(fmt.Sprintf("Download: [%s%s] %d%%\n",
		strings.Repeat("█", filled),
		strings.Repeat("░", 30-filled),
		progress))

	// Colored progress bar
	s.WriteString("\n")
	if progress < 33 {
		s.WriteString("\033[31m") // Red
	} else if progress < 66 {
		s.WriteString("\033[33m") // Yellow
	} else {
		s.WriteString("\033[32m") // Green
	}
	s.WriteString(fmt.Sprintf("Status: [%s%s] %d%%\033[0m\n",
		strings.Repeat("▓", filled),
		strings.Repeat("░", 30-filled),
		progress))

	// Multiple progress bars
	s.WriteString("\nTasks:\n")
	for i := 0; i < 5; i++ {
		taskProgress := ((m.animFrame + i*20) * 3) % 101
		taskFilled := taskProgress * 20 / 100
		s.WriteString(fmt.Sprintf("Task %d: [%s%s] %3d%%\n",
			i+1,
			strings.Repeat("=", taskFilled),
			strings.Repeat("-", 20-taskFilled),
			taskProgress))
	}

	// Gradient bar
	s.WriteString("\nGradient Bar:\n")
	gradientColors := []string{"196", "202", "208", "214", "220", "226", "190", "154", "118", "82", "46"}
	for i := 0; i < filled && i < len(gradientColors); i++ {
		s.WriteString(fmt.Sprintf("\033[48;5;%sm  \033[0m", gradientColors[i*len(gradientColors)/30]))
	}

	return s.String()
}

func (m AppModel) renderMatrixRainDemo() string {
	var s strings.Builder

	s.WriteString("\033[1mMatrix Rain Effect:\033[0m\n\n")

	// Create matrix rain effect
	chars := "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789"
	runes := []rune(chars)

	width := 60
	if m.width < 60 {
		width = m.width
	}
	height := 15

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Create falling effect
			offset := (m.animFrame + x*3 - y*2) % 40
			if offset < 10 {
				// Bright green at the head
				s.WriteString("\033[1;32m")
			} else if offset < 20 {
				// Normal green
				s.WriteString("\033[32m")
			} else if offset < 25 {
				// Dim green
				s.WriteString("\033[2;32m")
			} else {
				// Black/invisible
				s.WriteString("\033[30m")
			}

			// Random character
			charIndex := (x + y + m.animFrame/5) % len(runes)
			s.WriteString(string(runes[charIndex]))
		}
		s.WriteString("\033[0m\n")
	}

	return s.String()
}

func (m AppModel) renderSineWaveDemo() string {
	var s strings.Builder

	s.WriteString("\033[1mSine Wave Animation:\033[0m\n\n")

	// Draw sine wave
	amplitude := 8.0
	frequency := 0.3
	phase := float64(m.animFrame) * 0.1

	for y := -10; y <= 10; y++ {
		lineWidth := 60
		if m.width < 60 {
			lineWidth = m.width
		}

		for x := 0; x < lineWidth; x++ {
			// Calculate sine wave position
			sineY := amplitude * math.Sin(frequency*float64(x)+phase)

			// Check if we should draw at this position
			if int(sineY) == -y {
				// Color based on position
				hue := (x + m.animFrame) % 360
				color := hueToAnsi(hue)
				s.WriteString(fmt.Sprintf("\033[38;5;%dm●\033[0m", color))
			} else if y == 0 {
				s.WriteString("\033[90m─\033[0m")
			} else if x == 30 {
				s.WriteString("\033[90m│\033[0m")
			} else {
				s.WriteString(" ")
			}
		}
		s.WriteString("\n")
	}

	// Add info
	s.WriteString(fmt.Sprintf("\n\033[36mPhase: %.2f  Frequency: %.2f  Amplitude: %.1f\033[0m", phase, frequency, amplitude))

	return s.String()
}

func (m AppModel) renderAdminPanel() string {
	var s strings.Builder

	s.WriteString("\033[1;31m╔════════════════════════════════════╗\033[0m\n")
	s.WriteString("\033[1;31m║      🔒 ADMIN PANEL 🔒            ║\033[0m\n")
	s.WriteString("\033[1;31m╚════════════════════════════════════╝\033[0m\n\n")

	s.WriteString("\033[32m✓ Admin access granted\033[0m\n\n")

	// System info
	s.WriteString("\033[1mSystem Information:\033[0m\n")
	s.WriteString(fmt.Sprintf("• Uptime: %s\n", time.Since(startTime).Round(time.Second)))
	s.WriteString(fmt.Sprintf("• Terminal: %dx%d\n", m.width, m.height))
	s.WriteString(fmt.Sprintf("• Config loaded: %v\n", m.config != nil))
	s.WriteString(fmt.Sprintf("• Animation frame: %d\n", m.animFrame))

	s.WriteString("\n\033[1mCapabilities:\033[0m\n")
	s.WriteString("• \033[32m✓\033[0m VT100 sequences\n")
	s.WriteString("• \033[32m✓\033[0m ANSI colors (256)\n")
	s.WriteString("• \033[32m✓\033[0m Unicode support\n")
	s.WriteString("• \033[32m✓\033[0m Box drawing\n")
	s.WriteString("• \033[32m✓\033[0m Real-time updates\n")

	// Animated status indicator
	indicators := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	indicator := indicators[m.animFrame%len(indicators)]
	s.WriteString(fmt.Sprintf("\n\033[33m%s\033[0m System operational", indicator))

	return s.String()
}

// Helper function to convert hue to ANSI 256 color
func hueToAnsi(hue int) int {
	// Map hue (0-360) to ANSI 256 color codes (roughly)
	// Using colors 196-201 (reds), 202-207 (oranges), 208-213 (yellows),
	// 214-219 (greens), 220-225 (cyans), 226-231 (blues)
	normalizedHue := hue % 360
	colorIndex := normalizedHue * 36 / 360
	return 196 + colorIndex
}

// addToHistory adds an entry to the activity history
func (m *AppModel) addToHistory(entry string) {
	// Not used in this demo, but kept for compatibility
}
