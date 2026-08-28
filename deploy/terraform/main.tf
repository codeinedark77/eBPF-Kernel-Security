provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "driftnet_sg" {
  name        = "driftnet-c2-sg"
  description = "Allow inbound traffic for DriftNet C2 Dashboard"

  ingress {
    description = "HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Change to specific IP in production
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "driftnet_c2" {
  ami           = "ami-0c55b159cbfafe1f0" # Ubuntu 20.04 LTS
  instance_type = "t3.micro"
  security_groups = [aws_security_group.driftnet_sg.name]

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install docker.io docker-compose -y
              systemctl start docker
              systemctl enable docker
              
              # Pull and run the DriftNet dashboard
              # docker pull your-registry/driftnet-dashboard:latest
              # docker run -d -p 80:3000 your-registry/driftnet-dashboard:latest
              EOF

  tags = {
    Name = "DriftNet-C2-Server"
  }
}

output "public_ip" {
  value = aws_instance.driftnet_c2.public_ip
}
