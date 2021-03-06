# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "signature/version"

Gem::Specification.new do |s|
  s.name        = "signature-acd"
  s.version     = Signature::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Thomas Hanson", "CJ Lazell", "Thomas Hanson"]
  s.email       = ["thanson@acdcorp.com"]
  s.homepage    = "http://github.com/acdcorp/signature"
  s.summary     = %q{Simple key/secret based authentication for apis}
  s.description = %q{Simple key/secret based authentication for apis}

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency "jruby-openssl" if defined?(JRUBY_VERSION)
  s.add_development_dependency "rspec"
  s.add_development_dependency "em-spec"
  s.add_development_dependency "pry"
end
