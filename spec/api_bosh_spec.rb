# frozen_string_literal: true
require 'rspec'
require 'yaml'

describe "config/pcap-api.yml bosh properties" do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties })) }

  context 'when pcap-api.bosh is provided without mTLS' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'bosh' =>
          {
            'agent_port' => 9495,
            'director_url'=> 'https://bosh.service.cf.internal:8080',
            'token_scope'=> 'bosh.admin'
          }
      }
    end
    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['agent_port']).to be(9495)
      expect(pcap_api_conf['bosh']['director_url']).to include("https://bosh.service.cf.internal:8080")
      expect(pcap_api_conf['bosh']['token_scope']).to include('bosh.admin')
    end
  end

  context 'when pcap-api.bosh is provided with skip server verification' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'bosh' =>
          {
            'agent_port' => 9495,
            'director_url'=> 'https://bosh.service.cf.internal:8080',
            'token_scope'=> 'bosh.admin',
            'mtls' => {
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => true,
            }
          }
      }
    end
    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['agent_port']).to be(9495)
      expect(pcap_api_conf['bosh']['director_url']).to include("https://bosh.service.cf.internal:8080")
      expect(pcap_api_conf['bosh']['token_scope']).to include('bosh.admin')
      expect(pcap_api_conf['bosh']['mtls']['skip_verify']).to be(true)
    end
  end

  context 'when pcap-api.bosh is provided with mTLS configuration' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'bosh' =>
          {
            'agent_port' => 9495,
            'director_url'=> 'https://bosh.service.cf.internal:8080',
            'token_scope'=> 'bosh.admin',
            'mtls' => {
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => true,
            }
          }
      }
    end
    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['agent_port']).to be(9495)
      expect(pcap_api_conf['bosh']['director_url']).to include("https://bosh.service.cf.internal:8080")
      expect(pcap_api_conf['bosh']['token_scope']).to include('bosh.admin')
      expect(pcap_api_conf['bosh']['mtls']['skip_verify']).to be(true)
    end
  end
end