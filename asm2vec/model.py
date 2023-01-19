import torch
import torch.nn as nn

bce, sigmoid, softmax = nn.BCELoss(), nn.Sigmoid(), nn.Softmax(dim=1)

# TODO: Document how this shit works because wtf
class ASM2VEC(nn.Module):
    def __init__(self, vocab_size, function_size, embedding_size):
        super(ASM2VEC, self).__init__()
        # Dictionary of the token embeddings: v_t
        self.embeddings = nn.Embedding(
            vocab_size,
            embedding_size,
            _weight=(torch.rand(vocab_size, embedding_size) - 0.5) / embedding_size / 2,
        )
        # Dictionary of the function embeddings, \theta_f_s
        self.embeddings_f = nn.Embedding(
            function_size,
            2 * embedding_size,
            _weight=(torch.rand(function_size, 2 * embedding_size) - 0.5)
            / embedding_size
            / 2,
        )
        # Dictionary of outputs: Transposed v'_t
        self.embeddings_r = nn.Embedding(
            vocab_size,
            2 * embedding_size,
            _weight=torch.zeros(vocab_size, 2 * embedding_size),
        )
        # Where the old embeddings are stored once the training step is done
        self.old_embeddings_f = None

    def init_estimation_mode(self, function_size_new):
        device = self.embeddings.weight.device
        embedding_size = self.embeddings.embedding_dim

        embedding_weights = self.embeddings.weight
        self.embeddings = nn.Embedding.from_pretrained(embedding_weights)

        output_weights = self.embeddings_r.weight
        self.embeddings_r = nn.Embedding.from_pretrained(output_weights)

        self.old_embeddings_f = self.embeddings_f
        self.embeddings_f = nn.Embedding(
            function_size_new,
            2 * embedding_size,
            _weight=(
                (torch.rand(function_size_new, 2 * embedding_size) - 0.5)
                / embedding_size
                / 2
            ).to(device),
        )

    def v(self, inp):
        # Retrieve the embeddings for all the context tokens
        e = self.embeddings(inp[:, 1:])
        # Retrieve the embedding for the function, \theta_f_s
        v_f = self.embeddings_f(inp[:, 0])
        # Calculate CT(in_(j-1))
        v_prev = torch.cat([e[:, 0], (e[:, 1] + e[:, 2]) / 2], dim=1)
        # Calculate CT(in_(j+1))
        v_next = torch.cat([e[:, 3], (e[:, 4] + e[:, 5]) / 2], dim=1)
        # delta(in_j, f_s) = 1/3 * (\theta_f_s + CT(in_(j-1)) + CT(in_(j+1)))
        v = ((v_f + v_prev + v_next) / 3).unsqueeze(2)
        return v

    def forward(self, inp, pos, neg):
        device, batch_size = inp.device, inp.shape[0]
        v = self.v(inp)
        # negative sampling loss
        pred = torch.bmm(self.embeddings_r(torch.cat([pos, neg], dim=1)), v).squeeze()
        label = torch.cat(
            [torch.ones(batch_size, 1), torch.zeros(batch_size, neg.shape[1])], dim=1
        ).to(device)
        return bce(sigmoid(pred), label)

    def predict(self, inp, pos):
        device, batch_size = inp.device, inp.shape[0]
        v = self.v(inp)
        probs = torch.bmm(
            self.embeddings_r(
                torch.arange(self.embeddings_r.num_embeddings)
                .repeat(batch_size, 1)
                .to(device)
            ),
            v,
        ).squeeze(dim=2)
        return softmax(probs)
