package core

import (
	"testing"
)

func TestValidateFlowSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid src IP",
			spec: FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid dst IP",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid src MAC",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcMAC:  "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlowSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFlowSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTask(t *testing.T) {
	tests := []struct {
		name    string
		task    Task
		wantErr bool
	}{
		{
			name: "valid task",
			task: Task{
				Name:     "test task",
				Protocol: "tcp",
				Spec: FlowSpec{
					SrcIP:   "192.168.1.1",
					DstIP:   "192.168.1.2",
					SrcPort: 12345,
					DstPort: 80,
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			task: Task{
				Protocol: "tcp",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			task: Task{
				Name:     "test",
				Protocol: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTask(tt.task)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTask() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseBPS(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"100", 100, false},
		{"1k", 1000, false},
		{"1K", 1000, false},
		{"1m", 1000000, false},
		{"1M", 1000000, false},
		{"1g", 1000000000, false},
		{"1G", 1000000000, false},
		{"200k", 200000, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseBPS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBPS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseBPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIRequestToTask(t *testing.T) {
	task := APIRequestToTask("test", "description", "tcp", FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
	}, "eth0")

	if task.Name != "test" {
		t.Errorf("Name = %s, want test", task.Name)
	}
	if task.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", task.Protocol)
	}
	if task.Interface != "eth0" {
		t.Errorf("Interface = %s, want eth0", task.Interface)
	}
	if task.ID == "" {
		t.Error("ID should not be empty")
	}
}
