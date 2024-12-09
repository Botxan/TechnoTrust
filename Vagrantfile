Vagrant.configure("2") do |config|
  # Define the list of users and their associated passwords
  user_passwords = {
    "alice" => "123456",
    "bob" => "admin",
    "carol" => "12345678",
    "david" => "123456789",
    "eve" => "1234",
    "frank" => "12345",
    "grace" => "password",
    "hank" => "123",
    "iris" => "Aa123456"
  }

  # Global provisioning to update and install sshpass and git
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y sshpass git
  SHELL

  # Shared folder configuration
  config.vm.synced_folder "C:\\Users\\Botxan\\Desktop\\Oihan\\VM\\NS-Shared-Directory", "/shared", type: "virtualbox"

  # Define a helper method for machine provisioning
  def provision_machine(machine, username, password)
    machine.vm.box = "ubuntu/trusty64"
    machine.vm.box_version = "20191107.0.0"
    machine.vm.provision "shell", inline: <<-SHELL
      # Add user with specific password
      sudo useradd -m #{username}
      echo "#{username}:#{password}" | sudo chpasswd

      # Set root password to '1313'
      echo "root:1313" | sudo chpasswd
    SHELL
  end

  # Define each machine with its specific user, password, and network configuration
  config.vm.define "machine1" do |machine|
    provision_machine(machine, "alice", user_passwords["alice"])
    machine.vm.network "private_network", ip: "192.168.50.10"
  end

  config.vm.define "machine2" do |machine|
    provision_machine(machine, "bob", user_passwords["bob"])
    machine.vm.network "private_network", ip: "192.168.50.11"
  end

  config.vm.define "machine3" do |machine|
    provision_machine(machine, "carol", user_passwords["carol"])
    machine.vm.network "private_network", ip: "192.168.50.12"
    machine.vm.network "private_network", ip: "192.168.60.12"
  end

  config.vm.define "machine4" do |machine|
    provision_machine(machine, "david", user_passwords["david"])
    machine.vm.network "private_network", ip: "192.168.60.13"
  end

  config.vm.define "machine5" do |machine|
    provision_machine(machine, "eve", user_passwords["eve"])
    machine.vm.network "private_network", ip: "192.168.60.14"
  end

  config.vm.define "machine6" do |machine|
    provision_machine(machine, "frank", user_passwords["frank"])
    machine.vm.network "private_network", ip: "192.168.60.15"
    machine.vm.network "private_network", ip: "192.168.70.15"
  end

  config.vm.define "machine7" do |machine|
    provision_machine(machine, "grace", user_passwords["grace"])
    machine.vm.network "private_network", ip: "192.168.70.16"
  end

  config.vm.define "machine8" do |machine|
    provision_machine(machine, "hank", user_passwords["hank"])
    machine.vm.network "private_network", ip: "192.168.70.17"
  end

  config.vm.define "machine9" do |machine|
    provision_machine(machine, "iris", user_passwords["iris"])
    machine.vm.network "private_network", ip: "192.168.70.18"
    machine.vm.network "private_network", ip: "192.168.50.18"
  end
end
