require 'rubygems'
require 'rake/gempackagetask'
require 'rake/rdoctask'

$:.unshift(File.expand_path(File.dirname(__FILE__) + '/lib'))

require './lib/action_mailer/ar_sendmail'

ar_mailer_gemspec = Gem::Specification.new do |s|
  s.name = %q{VvanGemert-ar_mailer}
  s.version = ActionMailer::ARSendmail::VERSION
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Eric Hodel", "Adam Meehan", "Vincent van Gemert"]
  s.default_executable = %q{ar_sendmail}
  s.description = %q{Even delivering email to the local machine may take too long when you have to send hundreds of messages.  ar_mailer allows you to store messages into the database for later delivery by a separate process, ar_sendmail.}
  s.email = %q{vincent@floorplanner.com}
  s.executables = ["ar_sendmail"]
  s.extra_rdoc_files = ["History.txt", "LICENSE.txt", "README.rdoc"]
  s.files = [
    "History.txt",
    "LICENSE.txt",
    "README.rdoc",
    "Rakefile",
    "bin/ar_sendmail",
    "generators/ar_mailer/ar_mailer_generator.rb",
    "generators/ar_mailer/templates/migration.rb",
    "generators/ar_mailer/templates/model.rb",
    "lib/adzap-ar_mailer.rb",
    "lib/action_mailer/ar_mailer.rb",
    "lib/action_mailer/ar_sendmail.rb",
    "lib/smtp_tls.rb",
    "share/bsd/ar_sendmail",
    "share/linux/ar_sendmail",
    "share/linux/ar_sendmail.conf",
    "test/resources/action_mailer.rb",
    "test/test_armailer.rb",
    "test/test_arsendmail.rb",
    "test/test_helper.rb"
  ]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/VvanGemert/ar_mailer}
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{seattlerb}
  s.summary = %q{A two-phase delivery agent for ActionMailer}
  s.test_files = []
end

Rake::GemPackageTask.new(ar_mailer_gemspec) do |pkg|
  pkg.gem_spec = ar_mailer_gemspec
end

desc "Update ar_mailer.gemspec"
task :make_spec do
  File.open("adzap-ar_mailer.gemspec", "w") do |f|
    f.puts(ar_mailer_gemspec.to_ruby)
  end
end

desc "Build packages and install"
task :install => :package do
  sh %{sudo gem install --local --test pkg/VvanGemert-ar_mailer-#{ActionMailer::ARSendmail::VERSION}}
end
