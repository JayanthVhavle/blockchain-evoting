import time, datetime
import uuid
from Crypto.Signature import DSS
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto import Random
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect, render

from simulation.models import Vote, VoteBackup, Block
from simulation.merkle.merkle_tool import MerkleTools

def create(request):
    if request.method == 'POST':
        voter_id = request.POST.get('voter-id-input')
        vote = request.POST.get('vote-input')
        private_key = request.POST.get('private-key-input')

        # Create ballot as string vector
        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}|{}".format(voter_id, vote, timestamp)
        print('\ncasted ballot: {}\n'.format(ballot))
        signature = ''
        try:
            # Create signature
            priv_key = ECC.import_key(private_key)
            h = SHA3_256.new(ballot.encode('utf-8'))
            signature = DSS.new(priv_key, 'fips-186-3').sign(h)
            print('\nsignature: {}\n'.format(signature.hex()))

            # Verify the signature using registered public key
            pub_key = ECC.import_key(settings.PUBLIC_KEY)
            verifier = DSS.new(pub_key, 'fips-186-3')
        
            verifier.verify(h, signature)
            status = 'The ballot is signed successfully.'
            error = False
            request.session['voter-id']=voter_id
            request.session['vote']=vote
        except (ValueError, TypeError):
            status = 'The key is not registered.'
            error = True
        
        context = {
            'ballot': ballot,
            'signature': signature,
            'status': status,
            'error': error,
        }
        return render(request, 'ballot/status.html', context)

    context = {'voter_id': uuid.uuid4(), }
    return render(request, 'ballot/create.html', context)

def seal(request):
    if request.method == 'POST':
        ballot = request.POST.get('ballot_input')
        ballot_byte = ballot.encode('utf-8')
        ballot_hash = SHA3_256.new(ballot_byte).hexdigest()
        # Puzzle requirement: '0' * n (n leading zeros)
        puzzle, pcount = settings.PUZZLE, settings.PLENGTH
        nonce = 0

        # Try to solve puzzle
        start_time = time.time() # benchmark
        timestamp = datetime.datetime.now().timestamp() # mark the start of mining effort
        while True:
            block_hash = SHA3_256.new(("{}{}{}".format(ballot, nonce, timestamp).encode('utf-8'))).hexdigest()
            print('\ntrial hash: {}\n'.format(block_hash))
            if block_hash[:pcount] == puzzle:
               
                block_no = get_cur_block()
                v_id = request.session['voter-id']
                v_cand = request.session['vote']
                v_timestamp = timestamp
                del request.session['voter-id']
                del request.session['vote']

                block_no += 1
                # directly fill the values and the block id for simulation purpose
                new_vote = Vote(id=v_id, vote=v_cand, timestamp=v_timestamp, block_id=block_no)
                new_backup_vote = VoteBackup(id=v_id, vote=v_cand, timestamp=v_timestamp, block_id=block_no)
                # "Broadcast" to two nodes
                new_vote.save()
                new_backup_vote.save()
                print("#{} new vote: {}".format(block_no, new_vote)) # for sanity
                
                # Puzzle requirement: '0' * (n leading zeros)
                puzzle, pcount = settings.PUZZLE, settings.PLENGTH

                prev_hash = get_prev_hash()

                block_transactions = Vote.objects.filter(block_id=block_no).order_by('timestamp')
                root = MerkleTools()
                root.add_leaf([str(tx) for tx in block_transactions], True)
                root.make_tree()
                merkle_h = root.get_merkle_root()

                # Create the block
                block = Block(id=block_no, prev_h=prev_hash, merkle_h=merkle_h, h=block_hash, nonce=nonce, timestamp=timestamp)
                block.save()
                stop_time = time.time()
                print('\nBlock {} is mined\n'.format(block_no))                
                print("\nblock is sealed in {} seconds\n".format(stop_time-start_time))

                break
            nonce += 1

        
        context = {
            'prev_hash': prev_hash,
            'transaction_hash': ballot_hash,
            'nonce': nonce,
            'block_hash': block_hash,
            'timestamp': timestamp,
        }
        return render(request, 'ballot/seal.html', context)
    return redirect('ballot:create')

#Helpers
def get_cur_block():
    try:
        cur_block = Block.objects.latest('id')
        return cur_block.id
    except:
        return 1

def get_prev_hash():
    try:
        cur_block = Block.objects.latest('id')
        return cur_block.h
    except:
        return '0'*64